# frozen_string_literal: true

module Rack
  class Attack
    class RulesetValidator
      VALID_TYPES = %w[safelist blocklist throttle track].freeze
      NUMERIC_OPERATORS = %w[gt lt gte lte].freeze

      VALID_OPERATORS = %w[
        eq ne in not_in contains starts_with ends_with matches wildcard
        gt lt gte lte in_ip_range not_in_ip_range exists not_exists
      ].freeze

      VALID_TRANSFORMS = %w[lower upper url_decode length].freeze
      VALID_RULE_ORDERS = %w[cost insertion].freeze

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

      Result = Struct.new(:valid?, :errors, :warnings, keyword_init: true)

      def initialize(data)
        @data = data
        @errors = []
        @warnings = []
      end

      def validate
        data = normalize(@data)

        unless data.is_a?(Hash)
          return Result.new(valid?: false, errors: ["Ruleset must be a Hash"], warnings: [])
        end

        rules = data["rules"]
        unless rules.is_a?(Array)
          return Result.new(valid?: false, errors: ["Ruleset must contain a \"rules\" array"], warnings: [])
        end

        if data.key?("rule_order")
          unless VALID_RULE_ORDERS.include?(data["rule_order"])
            @errors << "\"rule_order\" must be one of: #{VALID_RULE_ORDERS.join(", ")}"
          end
        end

        seen_names = {}
        rules.each_with_index do |rule, index|
          validate_rule(rule, index)

          # Detect duplicate rule names
          if rule.is_a?(Hash)
            name = (rule["name"] || rule[:name]).to_s
            unless name.empty?
              if seen_names.key?(name)
                @warnings << "Rule \"#{name}\": duplicate rule name (first seen at rule ##{seen_names[name]})"
              else
                seen_names[name] = index
              end
            end
          end
        end

        if data.key?("jwt_keys")
          validate_jwt_keys(data["jwt_keys"])
        end

        Result.new(valid?: @errors.empty?, errors: @errors, warnings: @warnings)
      end

      private

      def normalize(data)
        case data
        when Hash
          data.each_with_object({}) do |(key, value), hash|
            hash[key.to_s] = normalize(value)
          end
        when Array
          data.map { |element| normalize(element) }
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

        name = rule["name"]
        type = rule["type"]
        condition = rule["condition"]
        enabled = rule["enabled"]
        limit = rule["limit"]
        period = rule["period"]
        key_fields = rule["key"]

        # Required fields
        unless name.is_a?(String) && !name.empty?
          @errors << "#{prefix}: missing or empty \"name\""
        else
          prefix = "Rule \"#{name}\""
        end

        unless rule.key?("type")
          @errors << "#{prefix}: missing \"type\""
        end

        if type && !VALID_TYPES.include?(type)
          @errors << "#{prefix}: invalid type \"#{type}\", must be one of: #{VALID_TYPES.join(", ")}"
        end

        if rule.key?("enabled") && ![true, false].include?(enabled)
          @errors << "#{prefix}: \"enabled\" must be a boolean"
        end

        if rule.key?("description") && !rule["description"].is_a?(String)
          @errors << "#{prefix}: \"description\" must be a string"
        end

        # Disabled rules only need name, type, enabled, and description validated.
        # Skip condition/throttle/key checks since the rule will never be evaluated.
        return if enabled == false

        unless rule.key?("condition")
          @errors << "#{prefix}: missing \"condition\""
        end

        # Throttle-specific fields
        if type == "throttle"
          unless limit.is_a?(Numeric) && limit > 0
            @errors << "#{prefix}: throttle requires a positive numeric \"limit\""
          end

          unless period.is_a?(Numeric) && period > 0
            @errors << "#{prefix}: throttle requires a positive numeric \"period\""
          end

          if limit.is_a?(Numeric) && limit > 100_000
            @warnings << "#{prefix}: throttle limit #{limit} is unusually high — verify this is intentional"
          end

          # Validate throttle key field names
          if key_fields.is_a?(Array)
            key_fields.each do |field|
              unless valid_field?(field.to_s)
                @errors << "#{prefix}: invalid key field \"#{field}\""
              end
            end
          end
        end

        # Validate condition structure
        validate_condition(condition, prefix) if condition
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

        and_conditions = condition["and"]
        or_conditions = condition["or"]
        not_condition = condition["not"]

        if condition.key?("and")
          unless and_conditions.is_a?(Array)
            @errors << "#{prefix}: \"and\" must be an Array"
            return
          end
          and_conditions.each { |sub_condition| validate_condition(sub_condition, prefix, depth: depth + 1) }
        elsif condition.key?("or")
          unless or_conditions.is_a?(Array)
            @errors << "#{prefix}: \"or\" must be an Array"
            return
          end
          or_conditions.each { |sub_condition| validate_condition(sub_condition, prefix, depth: depth + 1) }
        elsif condition.key?("not")
          validate_condition(not_condition, prefix, depth: depth + 1)
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

        # Validate value types for specific operators
        if leaf.key?("value") && operator.is_a?(String)
          value = leaf["value"]

          case operator
          when "matches"
            if value.is_a?(String)
              begin
                Regexp.new(value)
              rescue RegexpError => error
                @errors << "#{prefix}: invalid regex \"#{value}\": #{error.message}"
              end
            end
          when "in_ip_range", "not_in_ip_range"
            cidrs = value.is_a?(Array) ? value : [value]
            cidrs.each do |cidr|
              next unless cidr.is_a?(String)

              begin
                IPAddr.new(cidr)
              rescue IPAddr::InvalidAddressError
                @errors << "#{prefix}: invalid CIDR \"#{cidr}\""
              end
            end
          when *NUMERIC_OPERATORS
            unless value.is_a?(Numeric)
              @errors << "#{prefix}: operator \"#{operator}\" requires a numeric value, got #{value.class}"
            end
          end
        end

        if leaf.key?("transform")
          transforms = leaf["transform"]
          transforms = [transforms] unless transforms.is_a?(Array)
          transforms.each do |transform|
            unless VALID_TRANSFORMS.include?(transform)
              @errors << "#{prefix}: invalid transform \"#{transform}\", must be one of: #{VALID_TRANSFORMS.join(", ")}"
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

        jwt_keys.each_with_index do |entry, index|
          unless entry.is_a?(Hash)
            @errors << "jwt_keys[#{index}]: must be a Hash"
            next
          end
          entry = normalize(entry)
          algorithm = entry["algorithm"]
          key = entry["key"]
          unless algorithm.is_a?(String) && !algorithm.empty?
            @errors << "jwt_keys[#{index}]: missing or empty \"algorithm\""
          end
          unless key.is_a?(String) && !key.empty?
            @errors << "jwt_keys[#{index}]: missing or empty \"key\""
          end
        end
      end
    end
  end
end
