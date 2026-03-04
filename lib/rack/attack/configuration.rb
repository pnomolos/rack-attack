# frozen_string_literal: true

require "ipaddr"
require "json"
require "set"

module Rack
  class Attack
    class Configuration
      DEFAULT_BLOCKLISTED_RESPONDER = lambda { |_req| [403, { 'content-type' => 'text/plain' }, ["Forbidden\n"]] }

      DEFAULT_THROTTLED_RESPONDER = lambda do |req|
        if Rack::Attack.configuration.throttled_response_retry_after_header
          match_data = req.env['rack.attack.match_data']
          now = match_data[:epoch_time]
          retry_after = match_data[:period] - (now % match_data[:period])

          [429, { 'content-type' => 'text/plain', 'retry-after' => retry_after.to_s }, ["Retry later\n"]]
        else
          [429, { 'content-type' => 'text/plain' }, ["Retry later\n"]]
        end
      end

      attr_reader :safelists, :blocklists, :throttles, :tracks, :anonymous_blocklists, :anonymous_safelists
      attr_accessor :blocklisted_responder, :throttled_responder, :throttled_response_retry_after_header

      attr_reader :blocklisted_response, :throttled_response # Keeping these for backwards compatibility

      def blocklisted_response=(responder)
        warn "[DEPRECATION] Rack::Attack.blocklisted_response is deprecated. "\
          "Please use Rack::Attack.blocklisted_responder instead."
        @blocklisted_response = responder
      end

      def throttled_response=(responder)
        warn "[DEPRECATION] Rack::Attack.throttled_response is deprecated. "\
          "Please use Rack::Attack.throttled_responder instead"
        @throttled_response = responder
      end

      def initialize
        set_defaults
      end

      def safelist(name = nil, &block)
        safelist = Safelist.new(name, &block)

        if name
          @safelists[name] = safelist
        else
          @anonymous_safelists << safelist
        end
      end

      def blocklist(name = nil, &block)
        blocklist = Blocklist.new(name, &block)

        if name
          @blocklists[name] = blocklist
        else
          @anonymous_blocklists << blocklist
        end
      end

      def blocklist_ip(ip_address)
        @anonymous_blocklists << Blocklist.new do |request|
          request.ip && !request.ip.empty? && IPAddr.new(ip_address).include?(IPAddr.new(request.ip))
        end
      end

      def safelist_ip(ip_address)
        @anonymous_safelists << Safelist.new do |request|
          request.ip && !request.ip.empty? && IPAddr.new(ip_address).include?(IPAddr.new(request.ip))
        end
      end

      def throttle(name, options, &block)
        @throttles[name] = Throttle.new(name, options, &block)
      end

      def track(name, options = {}, &block)
        @tracks[name] = Track.new(name, options, &block)
      end

      def load_ruleset(source, replace: false, jwt_keys: nil)
        clear_configuration if replace

        data = parse_source(source)
        rules = data["rules"] || []
        jwt_config = jwt_keys || data["jwt_keys"]
        @jwt_keys = jwt_config

        rules.each do |rule|
          register_json_rule(rule, jwt_config: jwt_config)
        end

        rebuild_native_ruleset!
      end

      def safelisted?(request)
        native_result = evaluate_native(request)

        if native_result
          # Check native safelist result
          if native_result["safelisted"]
            name = native_result["safelisted"]
            request.env["rack.attack.matched"] = name
            request.env["rack.attack.match_type"] = :safelist
            Rack::Attack.instrument(request)
            return true
          end

          # Check block-based safelists (non-JSON rules only)
          @anonymous_safelists.any? { |sl| sl.matched_by?(request) } ||
            @safelists.any? { |n, sl| !@json_rule_names.include?(n) && sl.matched_by?(request) }
        else
          @anonymous_safelists.any? { |sl| sl.matched_by?(request) } ||
            @safelists.any? { |_name, sl| sl.matched_by?(request) }
        end
      end

      def blocklisted?(request)
        native_result = evaluate_native(request)

        if native_result
          if native_result["blocklisted"]
            name = native_result["blocklisted"]
            request.env["rack.attack.matched"] = name
            request.env["rack.attack.match_type"] = :blocklist
            Rack::Attack.instrument(request)
            return true
          end

          @anonymous_blocklists.any? { |bl| bl.matched_by?(request) } ||
            @blocklists.any? { |n, bl| !@json_rule_names.include?(n) && bl.matched_by?(request) }
        else
          @anonymous_blocklists.any? { |bl| bl.matched_by?(request) } ||
            @blocklists.any? { |_name, bl| bl.matched_by?(request) }
        end
      end

      def throttled?(request)
        native_result = evaluate_native(request)

        if native_result
          throttled = false

          # Process native throttle matches
          (native_result["throttle_matches"] || []).each do |tm|
            name = tm["name"]
            discriminator = tm["discriminator"]
            current_limit = tm["limit"]
            current_period = tm["period"]

            count = Rack::Attack.cache.count("#{name}:#{discriminator}", current_period)
            data = {
              discriminator: discriminator,
              count: count,
              period: current_period,
              limit: current_limit,
              epoch_time: Rack::Attack.cache.last_epoch_time
            }
            (request.env['rack.attack.throttle_data'] ||= {})[name] = data

            if count > current_limit
              request.env['rack.attack.matched'] = name
              request.env['rack.attack.match_discriminator'] = discriminator
              request.env['rack.attack.match_type'] = :throttle
              request.env['rack.attack.match_data'] = data
              Rack::Attack.instrument(request)
              throttled = true
            end
          end

          return true if throttled

          # Check block-based throttles
          @throttles.any? { |n, t| !@json_rule_names.include?(n) && t.matched_by?(request) }
        else
          @throttles.any? { |_name, t| t.matched_by?(request) }
        end
      end

      def tracked?(request)
        native_result = evaluate_native(request)

        if native_result
          # Instrument native track matches
          (native_result["tracked"] || []).each do |name|
            request.env["rack.attack.matched"] = name
            request.env["rack.attack.match_type"] = :track
            Rack::Attack.instrument(request)
          end

          # Check block-based tracks
          @tracks.each do |n, t|
            t.matched_by?(request) unless @json_rule_names.include?(n)
          end
        else
          @tracks.each_value do |t|
            t.matched_by?(request)
          end
        end
      end

      def simulate(**request_options)
        request = build_simulation_request(**request_options)
        safelisted_by = find_safelist_match(request)
        blocked_by = find_blocklist_match(request)
        throttle_matches = find_throttle_matches(request)
        track_matches = find_track_matches(request)

        SimulationResult.new(
          safelisted_by: safelisted_by,
          blocked_by: blocked_by,
          throttle_matches: throttle_matches,
          track_matches: track_matches
        )
      end

      def validate_ruleset(source)
        data = parse_source(source)
        RulesetValidator.new(data).validate
      end

      def simulate_throttle(count:, **request_options)
        request = build_simulation_request(**request_options)
        matches = find_throttle_matches(request)
        return SimulationResult.new if matches.empty?

        # Find the most restrictive matching throttle
        match = matches.min_by { |m| m[:limit] }
        exceeded = count > match[:limit]

        SimulationResult.new(
          throttle_matches: exceeded ? matches : []
        )
      end

      def clear_configuration
        set_defaults
      end

      private

      def set_defaults
        @safelists = {}
        @blocklists = {}
        @throttles = {}
        @tracks = {}
        @anonymous_blocklists = []
        @anonymous_safelists = []
        @throttled_response_retry_after_header = false

        @blocklisted_responder = DEFAULT_BLOCKLISTED_RESPONDER
        @throttled_responder = DEFAULT_THROTTLED_RESPONDER

        # Deprecated: Keeping these for backwards compatibility
        @blocklisted_response = nil
        @throttled_response = nil

        # JSON rule support
        @json_rules = []
        @json_rule_names = Set.new
        @jwt_keys = nil
        @native_ruleset = nil
      end

      def parse_source(source)
        case source
        when Hash
          deep_stringify_keys(source)
        when String
          if source.end_with?(".json") && File.exist?(source)
            JSON.parse(File.read(source))
          else
            JSON.parse(source)
          end
        else
          raise ArgumentError, "load_ruleset source must be a Hash, JSON string, or file path"
        end
      end

      def deep_stringify_keys(hash)
        hash.each_with_object({}) do |(k, v), h|
          h[k.to_s] = case v
                       when Hash then deep_stringify_keys(v)
                       when Array then v.map { |e| e.is_a?(Hash) ? deep_stringify_keys(e) : e }
                       else v
                       end
        end
      end

      def register_json_rule(json_rule, jwt_config:)
        name = json_rule["name"]
        type = json_rule["type"]
        condition = json_rule["condition"]

        @json_rules << json_rule
        @json_rule_names << name

        case type
        when "safelist"
          block = build_condition_block(condition, jwt_config)
          @safelists[name] = Safelist.new(name, &block)
        when "blocklist"
          block = build_condition_block(condition, jwt_config)
          @blocklists[name] = Blocklist.new(name, &block)
        when "throttle"
          limit = json_rule["limit"]
          period = json_rule["period"]
          key_fields = json_rule["key"] || ["ip.src"]
          block = build_throttle_block(condition, key_fields, jwt_config)
          @throttles[name] = Throttle.new(name, { limit: limit, period: period }, &block)
        when "track"
          block = build_condition_block(condition, jwt_config)
          @tracks[name] = Track.new(name, &block)
        end
      end

      def build_condition_block(condition, jwt_config)
        proc { |request| ConditionEvaluator.match?(condition, request, jwt_config: jwt_config) }
      end

      def build_throttle_block(condition, key_fields, jwt_config)
        proc do |request|
          if ConditionEvaluator.match?(condition, request, jwt_config: jwt_config)
            ConditionEvaluator.extract_throttle_key(key_fields, request, jwt_config: jwt_config)
          end
        end
      end

      def build_simulation_request(**opts)
        env = {
          "REQUEST_METHOD" => (opts[:method] || "GET").to_s.upcase,
          "PATH_INFO" => (opts[:path] || "/"),
          "QUERY_STRING" => (opts[:query_string] || ""),
          "REMOTE_ADDR" => (opts[:ip] || "127.0.0.1"),
          "HTTP_HOST" => (opts[:host] || "example.com"),
          "rack.input" => StringIO.new(opts[:body] || ""),
          "SERVER_NAME" => (opts[:host] || "example.com"),
          "SERVER_PORT" => "80"
        }

        env["HTTP_USER_AGENT"] = opts[:user_agent] if opts[:user_agent]
        env["CONTENT_LENGTH"] = opts[:body].bytesize.to_s if opts[:body] && !opts[:body].empty?

        if opts[:headers].is_a?(Hash)
          opts[:headers].each do |name, value|
            env_key = "HTTP_#{name.to_s.upcase.tr('-', '_')}"
            env[env_key] = value.to_s
          end
        end

        if opts[:cookies].is_a?(Hash)
          env["HTTP_COOKIE"] = opts[:cookies].map { |k, v| "#{k}=#{v}" }.join("; ")
        end

        Request.new(env)
      end

      def find_safelist_match(request)
        # Check named safelists
        @safelists.each do |name, safelist|
          return name if safelist.block.call(request)
        end

        # Check anonymous safelists
        @anonymous_safelists.each do |safelist|
          return safelist.name if safelist.block.call(request)
        end

        nil
      end

      def find_blocklist_match(request)
        @blocklists.each do |name, blocklist|
          return name if blocklist.block.call(request)
        end

        @anonymous_blocklists.each do |blocklist|
          return blocklist.name if blocklist.block.call(request)
        end

        nil
      end

      def find_throttle_matches(request)
        matches = []

        @throttles.each do |name, throttle|
          discriminator = throttle.block.call(request)
          next unless discriminator

          if Rack::Attack.throttle_discriminator_normalizer
            discriminator = Rack::Attack.throttle_discriminator_normalizer.call(discriminator)
          end

          current_limit = throttle.limit.respond_to?(:call) ? throttle.limit.call(request) : throttle.limit
          current_period = throttle.period.respond_to?(:call) ? throttle.period.call(request) : throttle.period

          matches << {
            name: name,
            discriminator: discriminator,
            limit: current_limit,
            period: current_period
          }
        end

        matches
      end

      def find_track_matches(request)
        names = []

        @tracks.each do |name, track_rule|
          filter = track_rule.filter
          if filter.is_a?(Throttle)
            # For throttle-based tracks, check if discriminator is present
            discriminator = filter.block.call(request)
            names << name if discriminator
          else
            names << name if filter.block.call(request)
          end
        end

        names
      end

      def rebuild_native_ruleset!
        @native_ruleset = if @json_rules.any?
                            NativeBridge.compile_ruleset(@json_rules, jwt_keys: @jwt_keys)
                          end
      end

      def evaluate_native(request)
        return nil unless @native_ruleset

        cache_key = "rack.attack.native_result"
        return request.env[cache_key] if request.env.key?(cache_key)

        native_request = NativeBridge.request_to_native(request)
        result = @native_ruleset.evaluate(native_request)
        # serde_magnus returns symbol keys; normalize to string keys
        result = stringify_native_result(result)
        request.env[cache_key] = result
        result
      rescue StandardError => e
        warn "[Rack::Attack] Native evaluation failed: #{e.message}"
        request.env[cache_key] = nil
        nil
      end

      def stringify_native_result(result)
        return result unless result.is_a?(Hash)

        stringified = {}
        result.each do |k, v|
          sk = k.to_s
          stringified[sk] = case v
                            when Array
                              v.map { |e| e.is_a?(Hash) ? stringify_native_result(e) : e }
                            when Hash
                              stringify_native_result(v)
                            else
                              v
                            end
        end
        stringified
      end
    end
  end
end
