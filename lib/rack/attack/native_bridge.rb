# frozen_string_literal: true

require "set"

module Rack
  class Attack
    module NativeBridge
      @available = nil

      class << self
        def available?
          if @available.nil?
            @available = begin
              require "rack_attack_native"
              true
            rescue LoadError
              false
            end
          end
          @available
        end

        def compile_ruleset(rules_array, jwt_keys: nil)
          return nil unless available?

          json_data = { "rules" => rules_array }
          json_data["jwt_keys"] = jwt_keys if jwt_keys

          begin
            rule_set = RackAttackNative::RuleSet.from_json(JSON.generate(json_data))
            # Cache which field categories the ruleset actually needs
            @required_fields = rule_set.required_fields.to_set
            rule_set
          rescue StandardError => e
            warn "[Rack::Attack] Failed to compile native ruleset: #{e.message}"
            nil
          end
        end

        def request_to_native(request, required_fields = @required_fields)
          env = request.env

          data = {
            "path" => request.path || "",
            "method" => request.request_method || "",
            "ip" => request.ip || ""
          }

          if required_fields.nil?
            # Fallback: send everything (backward compat)
            return request_to_native_full(request, env, data)
          end

          data["user_agent"] = request.user_agent if required_fields.include?("user_agent")
          data["host"] = request.host if required_fields.include?("host")
          data["query_string"] = (request.query_string || "") if required_fields.include?("query_string")
          data["content_length"] = (request.content_length || 0).to_i if required_fields.include?("content_length")
          data["authorization"] = env["HTTP_AUTHORIZATION"] if required_fields.include?("authorization")

          if required_fields.include?("body") && request.body
            request.body.rewind
            data["body"] = request.body.read
            request.body.rewind
          end

          if required_fields.include?("headers")
            headers = {}
            env.each do |key, value|
              next unless key.is_a?(String) && value.is_a?(String)

              if key.start_with?("HTTP_") && key != "HTTP_HOST" && key != "HTTP_USER_AGENT" && key != "HTTP_AUTHORIZATION"
                header_name = key[5..].downcase.tr("_", "-")
                headers[header_name] = value
              end
            end
            data["headers"] = headers
          end

          if required_fields.include?("cookies") && request.respond_to?(:cookies) && request.cookies.is_a?(Hash)
            data["cookies"] = request.cookies
          end

          data
        end

        private

        def request_to_native_full(request, env, data)
          headers = {}
          cookies = {}

          env.each do |key, value|
            next unless key.is_a?(String) && value.is_a?(String)

            if key.start_with?("HTTP_") && key != "HTTP_HOST" && key != "HTTP_USER_AGENT" && key != "HTTP_AUTHORIZATION"
              header_name = key[5..].downcase.tr("_", "-")
              headers[header_name] = value
            end
          end

          if request.respond_to?(:cookies) && request.cookies.is_a?(Hash)
            cookies = request.cookies
          end

          body = nil
          if request.body
            request.body.rewind
            body = request.body.read
            request.body.rewind
          end

          data.merge!(
            "user_agent" => request.user_agent,
            "host" => request.host,
            "query_string" => request.query_string || "",
            "content_length" => (request.content_length || 0).to_i,
            "authorization" => env["HTTP_AUTHORIZATION"],
            "body" => body,
            "headers" => headers,
            "cookies" => cookies
          )

          data
        end
      end
    end
  end
end
