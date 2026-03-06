# frozen_string_literal: true

require "json"
require "set"

module Rack
  class Attack
    module NativeBridge
      # Maximum body bytes forwarded to the native engine.
      # Prevents reading a multi-GB upload entirely into memory when a rule
      # only needs to inspect the first portion (e.g., an oversized-body rule
      # that fires at the 10 MB threshold).
      MAX_BODY_SIZE = 10 * 1024 * 1024 # 10 MB

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

        def compile_ruleset(rules_array, jwt_keys: nil, rule_order: nil)
          return nil unless available?

          json_data = { "rules" => rules_array }
          json_data["jwt_keys"] = jwt_keys if jwt_keys
          json_data["rule_order"] = rule_order if rule_order

          begin
            rule_set = RackAttackNative::RuleSet.from_json(JSON.generate(json_data))
            rule_set
          rescue StandardError => error
            warn "[Rack::Attack] Failed to compile native ruleset: #{error.message}"
            nil
          end
        end

        def request_to_native(request, required_fields = nil)
          if required_fields.nil?
            # Fallback: send everything (backward compat)
            return build_request_data(request, all_fields: true)
          end

          build_request_data(request, required_fields: required_fields)
        end

        private

        def build_request_data(request, all_fields: false, required_fields: nil)
          env = request.env

          data = {
            "path" => request.path || "",
            "method" => request.request_method || "",
            "ip" => request.ip || ""
          }

          need = ->(field) { all_fields || required_fields.include?(field) }

          data["user_agent"] = request.user_agent if need.call("user_agent")
          data["host"] = request.host if need.call("host")
          data["query_string"] = (request.query_string || "") if need.call("query_string")
          data["content_length"] = (request.content_length || 0).to_i if need.call("content_length")
          data["authorization"] = env["HTTP_AUTHORIZATION"] if need.call("authorization")

          body = request.body
          if need.call("body") && body
            body.rewind if body.respond_to?(:rewind)
            # Read at most MAX_BODY_SIZE bytes to avoid exhausting memory on huge uploads.
            data["body"] = body.read(MAX_BODY_SIZE)
            body.rewind if body.respond_to?(:rewind)
          end

          if need.call("headers")
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

          cookies = request.respond_to?(:cookies) ? request.cookies : nil
          if need.call("cookies") && cookies.is_a?(Hash)
            data["cookies"] = cookies
          end

          data
        end
      end
    end
  end
end
