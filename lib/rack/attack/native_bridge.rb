# frozen_string_literal: true

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
            RackAttackNative::RuleSet.from_json(JSON.generate(json_data))
          rescue StandardError => e
            warn "[Rack::Attack] Failed to compile native ruleset: #{e.message}"
            nil
          end
        end

        def request_to_native(request)
          env = request.env

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

          {
            "path" => request.path || "",
            "method" => request.request_method || "",
            "ip" => request.ip || "",
            "user_agent" => request.user_agent,
            "host" => request.host,
            "query_string" => request.query_string || "",
            "content_length" => (request.content_length || 0).to_i,
            "authorization" => env["HTTP_AUTHORIZATION"],
            "body" => body,
            "headers" => headers,
            "cookies" => cookies
          }
        end
      end
    end
  end
end
