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
