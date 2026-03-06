# frozen_string_literal: true

require "ipaddr"
require "json"
require "openssl"
require "uri"

module Rack
  class Attack
    module ConditionEvaluator
      # Maximum body bytes read to prevent exhausting memory on large uploads.
      # Rules that inspect body content (body.raw, body.json) will only see up
      # to this many bytes. This matches the common "oversized-body" rule threshold.
      MAX_BODY_SIZE = 10 * 1024 * 1024 # 10 MB

      # Thread-safe cache for compiled Regexp objects, keyed by pattern string.
      # Avoids recompiling the same pattern on every request evaluation.
      REGEX_CACHE_MUTEX = Mutex.new
      REGEX_CACHE_MAX   = 1000
      @regex_cache = {}

      class << self
        def match?(condition, request, jwt_config: nil)
          return true if condition.nil?

          ctx = EvalContext.new(request, jwt_config)
          ctx.evaluate(condition)
        end

        def extract_throttle_key(key_fields, request, jwt_config: nil)
          ctx = EvalContext.new(request, jwt_config)
          parts = key_fields.map { |field| ctx.extract_field(field) }
          return nil if parts.any?(&:nil?)

          parts.join(":")
        end

        # Returns a cached Regexp for +pattern+, compiling it only on first use.
        # Raises RegexpError for invalid patterns (callers should rescue as needed).
        # The cache is bounded to REGEX_CACHE_MAX entries; when full it is cleared
        # entirely and repopulated from scratch (simple but avoids both unbounded
        # growth and the performance cliff of never caching new patterns).
        def compile_regex(pattern)
          REGEX_CACHE_MUTEX.synchronize do
            cached = @regex_cache[pattern]
            return cached if cached

            compiled = Regexp.new(pattern)
            @regex_cache.clear if @regex_cache.size >= REGEX_CACHE_MAX
            @regex_cache[pattern] = compiled
            compiled
          end
        end

        # Clears the compiled regex cache. Useful after reloading rulesets to
        # free patterns from previous configurations.
        def clear_regex_cache!
          REGEX_CACHE_MUTEX.synchronize { @regex_cache.clear }
        end
      end

      class EvalContext
        def initialize(request, jwt_config)
          @request = request
          @jwt_config = jwt_config
          @jwt_cache = {}
        end

        def evaluate(condition)
          condition = symbolize_condition(condition)

          if condition.key?(:and)
            condition[:and].all? { |sub_cond| evaluate(sub_cond) }
          elsif condition.key?(:or)
            condition[:or].any? { |sub_cond| evaluate(sub_cond) }
          elsif condition.key?(:not)
            !evaluate(condition[:not])
          elsif condition.key?(:field)
            evaluate_leaf(condition)
          else
            false
          end
        end

        def extract_field(name)
          case name
          when "ip.src"
            @request.ip
          when /\Ahttp\./
            extract_http_field(name)
          when /\Ajwt\./
            extract_jwt_field(name)
          else
            nil
          end
        end

        private

        def extract_http_field(name)
          case name
          when "http.request.uri.path"
            @request.path
          when "http.request.method"
            @request.request_method
          when "http.user_agent"
            @request.user_agent
          when "http.host"
            @request.host
          when "http.request.uri.query"
            @request.query_string
          when "http.request.uri"
            query = @request.query_string
            if query && !query.empty?
              "#{@request.path}?#{query}"
            else
              @request.path
            end
          when "http.request.uri.path.extension"
            ext = File.extname(@request.path)
            ext.empty? ? nil : ext[1..]
          when "http.request.body.size"
            (@request.content_length || 0).to_i.to_s
          when "http.request.body.raw"
            body = @request.body
            return nil unless body

            body.rewind if body.respond_to?(:rewind)
            content = body.read(MAX_BODY_SIZE)
            body.rewind if body.respond_to?(:rewind)
            content
          when /\Ahttp\.request\.headers\["([^"]+)"\]\z/
            header_name = Regexp.last_match(1)
            env_key = "HTTP_#{header_name.upcase.tr('-', '_')}"
            @request.env[env_key]
          when /\Ahttp\.request\.cookies\["([^"]+)"\]\z/
            cookie_name = Regexp.last_match(1)
            @request.cookies[cookie_name]
          when /\Ahttp\.request\.uri\.args\["([^"]+)"\]\z/
            param_name = Regexp.last_match(1)
            parse_query_params[param_name]
          when /\Ahttp\.request\.body\.json\["([^"]+)"\]\z/
            json_key = Regexp.last_match(1)
            keys = json_key.split(".")
            parse_body_json&.dig(*keys)&.to_s
          end
        end

        def extract_jwt_field(name)
          case name
          when /\Ajwt\.payload\["([^"]+)"\]\z/
            claim = Regexp.last_match(1)
            decode_jwt_payload&.dig(claim)&.to_s
          when /\Ajwt\.header\["([^"]+)"\]\z/
            header_field = Regexp.last_match(1)
            decode_jwt_header&.dig(header_field)&.to_s
          when /\Ajwt\.verified_payload\["([^"]+)"\]\z/
            claim = Regexp.last_match(1)
            verify_jwt_payload&.dig(claim)&.to_s
          when "jwt.valid"
            verify_jwt_valid ? "true" : nil
          end
        end

        def symbolize_condition(cond)
          return cond if cond.is_a?(Hash) && cond.keys.all? { |k| k.is_a?(Symbol) }

          if cond.is_a?(Hash)
            cond.each_with_object({}) do |(key, value), hash|
              hash[key.to_sym] = value
            end
          else
            cond
          end
        end

        def evaluate_leaf(leaf)
          field_name = leaf[:field]
          operator = leaf[:operator]
          value = leaf[:value]
          transforms = leaf[:transform]

          field_val = extract_field(field_name)

          # Handle existence operators before transforms
          case operator
          when "exists"
            return !field_val.nil? && !field_val.empty?
          when "not_exists"
            return field_val.nil? || field_val.empty?
          end

          return false if field_val.nil?

          field_val = apply_transforms(field_val, transforms) if transforms

          apply_operator(operator, field_val, value)
        end

        def apply_transforms(value, transforms)
          transforms = [transforms] unless transforms.is_a?(Array)

          transforms.each do |transform|
            value = case transform
                    when "lower"
                      value.downcase
                    when "upper"
                      value.upcase
                    when "url_decode"
                      URI.decode_www_form_component(value)
                    when "length"
                      value.length.to_s
                    else
                      value
                    end
          end

          value
        end

        def apply_operator(op, field_val, comparison_val)
          case op
          when "eq"
            if comparison_val.is_a?(Numeric)
              numeric_compare(field_val) { |num| num == comparison_val }
            else
              field_val == comparison_val.to_s
            end
          when "ne"
            if comparison_val.is_a?(Numeric)
              numeric_compare(field_val) { |num| num != comparison_val }
            else
              field_val != comparison_val.to_s
            end
          when "in"
            Array(comparison_val).any? { |item| field_val == item.to_s }
          when "not_in"
            Array(comparison_val).none? { |item| field_val == item.to_s }
          when "contains"
            field_val.include?(comparison_val.to_s)
          when "starts_with"
            field_val.start_with?(comparison_val.to_s)
          when "ends_with"
            field_val.end_with?(comparison_val.to_s)
          when "matches"
            begin
              !!(field_val =~ ConditionEvaluator.compile_regex(comparison_val.to_s))
            rescue RegexpError
              false
            end
          when "wildcard"
            File.fnmatch(comparison_val.to_s, field_val, File::FNM_PATHNAME)
          when "gt"
            numeric_compare(field_val) { |num| num > comparison_val }
          when "lt"
            numeric_compare(field_val) { |num| num < comparison_val }
          when "gte"
            numeric_compare(field_val) { |num| num >= comparison_val }
          when "lte"
            numeric_compare(field_val) { |num| num <= comparison_val }
          when "in_ip_range"
            ip_in_ranges?(field_val, Array(comparison_val))
          when "not_in_ip_range"
            !ip_in_ranges?(field_val, Array(comparison_val))
          else
            false
          end
        end

        def numeric_compare(str_val)
          num = Float(str_val)
          yield num
        rescue ArgumentError, TypeError
          false
        end

        def ip_in_ranges?(ip_str, ranges)
          ip = IPAddr.new(ip_str)
          ranges.any? { |range| IPAddr.new(range).include?(ip) }
        rescue IPAddr::InvalidAddressError
          false
        end

        def parse_query_params
          @query_params ||= begin
            qs = @request.query_string
            return {} if qs.nil? || qs.empty?

            URI.decode_www_form(qs).to_h
          rescue ArgumentError
            {}
          end
        end

        def parse_body_json
          return @body_json if defined?(@body_json)

          @body_json = begin
            body = @request.body
            return nil unless body

            body.rewind if body.respond_to?(:rewind)
            # Read at most MAX_BODY_SIZE bytes to avoid exhausting memory on huge uploads.
            content = body.read(MAX_BODY_SIZE)
            body.rewind if body.respond_to?(:rewind)
            return nil if content.nil? || content.empty?

            JSON.parse(content)
          rescue JSON::ParserError, IOError, Errno::EBADF
            nil
          end
        end

        # URL-safe Base64 decode without requiring the base64 gem
        # (removed from Ruby 4.0 stdlib). Uses pack/unpack instead.
        def urlsafe_decode64(str)
          str = str.tr("-_", "+/")
          str += "=" * ((4 - str.length % 4) % 4)
          str.unpack1("m0")
        end

        # JWT helpers — lazy decode with caching

        def jwt_token
          @jwt_token ||= begin
            auth = @request.env["HTTP_AUTHORIZATION"]
            return nil unless auth

            match = auth.match(/\ABearer\s+(.+)\z/i)
            match ? match[1] : nil
          end
        end

        def decode_jwt_payload
          return @jwt_cache[:payload] if @jwt_cache.key?(:payload)

          @jwt_cache[:payload] = begin
            token = jwt_token
            return nil unless token

            parts = token.split(".")
            return nil if parts.length != 3

            payload_b64 = parts[1]
            payload_json = urlsafe_decode64(payload_b64)
            JSON.parse(payload_json)
          rescue StandardError => e
            warn "[Rack::Attack] JWT payload decode failed: #{e.message}"
            nil
          end
        end

        def decode_jwt_header
          return @jwt_cache[:header] if @jwt_cache.key?(:header)

          @jwt_cache[:header] = begin
            token = jwt_token
            return nil unless token

            parts = token.split(".")
            return nil if parts.length != 3

            header_b64 = parts[0]
            header_json = urlsafe_decode64(header_b64)
            JSON.parse(header_json)
          rescue StandardError => e
            warn "[Rack::Attack] JWT header decode failed: #{e.message}"
            nil
          end
        end

        def verify_jwt_payload
          return @jwt_cache[:verified_payload] if @jwt_cache.key?(:verified_payload)

          @jwt_cache[:verified_payload] = begin
            verified = verify_jwt
            verified ? verified["payload"] : nil
          end
        end

        def verify_jwt_valid
          return @jwt_cache[:valid] if @jwt_cache.key?(:valid)

          @jwt_cache[:valid] = !!verify_jwt
        end

        def verify_jwt
          return @jwt_cache[:verified] if @jwt_cache.key?(:verified)

          @jwt_cache[:verified] = begin
            token = jwt_token
            return nil unless token
            return nil unless @jwt_config && @jwt_config.is_a?(Array) && !@jwt_config.empty?

            # Try the jwt gem first
            if defined?(::JWT)
              verify_with_jwt_gem(token)
            else
              nil # Without the jwt gem, verification is not possible
            end
          end
        end

        def verify_with_jwt_gem(token)
          @jwt_config.each do |key_entry|
            algorithm = key_entry["algorithm"] || key_entry[:algorithm]
            raw_key = key_entry["key"] || key_entry[:key]
            next unless algorithm && raw_key

            begin
              key = coerce_jwt_key(algorithm, raw_key)
              decoded = ::JWT.decode(token, key, true, { algorithm: algorithm })
              return { "payload" => decoded[0], "header" => decoded[1] }
            rescue ::JWT::DecodeError
              next
            end
          end
          nil
        end

        # Coerce a raw key string into the appropriate type for the JWT gem.
        # HMAC algorithms use the raw string; RSA/EC/PS need OpenSSL key objects.
        def coerce_jwt_key(algorithm, raw_key)
          case algorithm
          when /\ARS|PS/  # RSA or PSS
            raw_key.is_a?(String) ? OpenSSL::PKey::RSA.new(raw_key) : raw_key
          when /\AES/     # ECDSA
            raw_key.is_a?(String) ? OpenSSL::PKey::EC.new(raw_key) : raw_key
          else            # HMAC (HS256, HS384, HS512)
            raw_key
          end
        end
      end
    end
  end
end
