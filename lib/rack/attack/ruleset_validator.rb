# frozen_string_literal: true

module Rack
  class Attack
    class RulesetValidator
      VALID_TYPES = %w[safelist blocklist throttle track].freeze

      VALID_OPERATORS = %w[
        eq ne in not_in contains starts_with ends_with matches wildcard
        gt lt gte lte in_ip_range not_in_ip_range exists not_exists
      ].freeze

      VALID_TRANSFORMS = %w[lower upper url_decode length].freeze

      STATIC_FIELDS = %w[
        ip.src
        http.request.uri.path
        http.request.method
        http.user_agent
        http.host
        http.request.uri.query
        http.request.uri
        http.request.uri.path.extension
        http.request.body.size
        http.request.body.raw
        jwt.valid
      ].freeze

      DYNAMIC_FIELD_PATTERNS = [
        /\Ahttp\.request\.headers\["[^"]+"\]\z/,
        /\Ahttp\.request\.cookies\["[^"]+"\]\z/,
        /\Ahttp\.request\.uri\.args\["[^"]+"\]\z/,
        /\Ahttp\.request\.body\.json\["[^"]+"\]\z/,
        /\Ajwt\.payload\["[^"]+"\]\z/,
        /\Ajwt\.header\["[^"]+"\]\z/,
        /\Ajwt\.verified_payload\["[^"]+"\]\z/
      ].freeze

      Result = Struct.new(:valid?, :errors, keyword_init: true)

      def initialize(data)
        @data = data
        @errors = []
      end

      def validate
        data = normalize(@data)

        unless data.is_a?(Hash)
          return Result.new(valid?: false, errors: ["Ruleset must be a Hash"])
        end

        rules = data["rules"]
        unless rules.is_a?(Array)
          return Result.new(valid?: false, errors: ["Ruleset must contain a \"rules\" array"])
        end

        rules.each_with_index do |rule, i|
          validate_rule(rule, i)
        end

        if data.key?("jwt_keys")
          validate_jwt_keys(data["jwt_keys"])
        end

        Result.new(valid?: @errors.empty?, errors: @errors)
      end

      private

      def normalize(data)
        case data
        when Hash
          data.each_with_object({}) do |(k, v), h|
            h[k.to_s] = normalize(v)
          end
        when Array
          data.map { |e| normalize(e) }
        else
          data
        end
      end

      def validate_rule(rule, index)
        prefix = "Rule ##{index}"

        unless rule.is_a?(Hash)
          @errors << "#{prefix}: must be a Hash"
          return
        end

        rule = normalize(rule)

        # Required fields
        unless rule["name"].is_a?(String) && !rule["name"].empty?
          @errors << "#{prefix}: missing or empty \"name\""
        else
          prefix = "Rule \"#{rule["name"]}\""
        end

        unless rule.key?("type")
          @errors << "#{prefix}: missing \"type\""
        end

        if rule["type"] && !VALID_TYPES.include?(rule["type"])
          @errors << "#{prefix}: invalid type \"#{rule["type"]}\", must be one of: #{VALID_TYPES.join(", ")}"
        end

        unless rule.key?("condition")
          @errors << "#{prefix}: missing \"condition\""
        end

        # Throttle-specific fields
        if rule["type"] == "throttle"
          unless rule["limit"].is_a?(Numeric) && rule["limit"] > 0
            @errors << "#{prefix}: throttle requires a positive numeric \"limit\""
          end

          unless rule["period"].is_a?(Numeric) && rule["period"] > 0
            @errors << "#{prefix}: throttle requires a positive numeric \"period\""
          end
        end

        # Validate condition structure
        validate_condition(rule["condition"], prefix) if rule["condition"]
      end

      def validate_condition(condition, prefix, depth: 0)
        if depth > 20
          @errors << "#{prefix}: condition nesting too deep (max 20)"
          return
        end

        unless condition.is_a?(Hash)
          @errors << "#{prefix}: condition must be a Hash"
          return
        end

        condition = normalize(condition)

        if condition.key?("and")
          unless condition["and"].is_a?(Array)
            @errors << "#{prefix}: \"and\" must be an Array"
            return
          end
          condition["and"].each { |c| validate_condition(c, prefix, depth: depth + 1) }
        elsif condition.key?("or")
          unless condition["or"].is_a?(Array)
            @errors << "#{prefix}: \"or\" must be an Array"
            return
          end
          condition["or"].each { |c| validate_condition(c, prefix, depth: depth + 1) }
        elsif condition.key?("not")
          validate_condition(condition["not"], prefix, depth: depth + 1)
        elsif condition.key?("field")
          validate_leaf_condition(condition, prefix)
        else
          @errors << "#{prefix}: condition must have \"and\", \"or\", \"not\", or \"field\" key"
        end
      end

      def validate_leaf_condition(leaf, prefix)
        field = leaf["field"]
        operator = leaf["operator"]

        unless field.is_a?(String) && !field.empty?
          @errors << "#{prefix}: condition missing or empty \"field\""
          return
        end

        unless valid_field?(field)
          @errors << "#{prefix}: unknown field \"#{field}\""
        end

        unless operator.is_a?(String) && VALID_OPERATORS.include?(operator)
          @errors << "#{prefix}: invalid operator \"#{operator}\", must be one of: #{VALID_OPERATORS.join(", ")}"
        end

        # exists/not_exists don't require a value
        if operator && !%w[exists not_exists].include?(operator)
          unless leaf.key?("value")
            @errors << "#{prefix}: condition with operator \"#{operator}\" requires a \"value\""
          end
        end

        if leaf.key?("transform")
          transforms = leaf["transform"]
          transforms = [transforms] unless transforms.is_a?(Array)
          transforms.each do |t|
            unless VALID_TRANSFORMS.include?(t)
              @errors << "#{prefix}: invalid transform \"#{t}\", must be one of: #{VALID_TRANSFORMS.join(", ")}"
            end
          end
        end
      end

      def valid_field?(field)
        return true if STATIC_FIELDS.include?(field)

        DYNAMIC_FIELD_PATTERNS.any? { |pattern| field.match?(pattern) }
      end

      def validate_jwt_keys(jwt_keys)
        unless jwt_keys.is_a?(Array)
          @errors << "\"jwt_keys\" must be an Array"
          return
        end

        jwt_keys.each_with_index do |entry, i|
          unless entry.is_a?(Hash)
            @errors << "jwt_keys[#{i}]: must be a Hash"
            next
          end
          entry = normalize(entry)
          unless entry["algorithm"].is_a?(String) && !entry["algorithm"].empty?
            @errors << "jwt_keys[#{i}]: missing or empty \"algorithm\""
          end
          unless entry["key"].is_a?(String) && !entry["key"].empty?
            @errors << "jwt_keys[#{i}]: missing or empty \"key\""
          end
        end
      end
    end
  end
end
