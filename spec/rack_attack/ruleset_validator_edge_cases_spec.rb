# frozen_string_literal: true

require_relative "test_helper"

describe "RulesetValidator edge cases" do
  def validate(data)
    Rack::Attack::RulesetValidator.new(data).validate
  end

  # --- Nesting depth ---

  describe "nesting depth limits" do
    it "condition nested exactly 20 levels deep is valid" do
      inner = { "field" => "ip.src", "operator" => "eq", "value" => "1.2.3.4" }
      20.times { inner = { "and" => [inner] } }

      result = validate({
        "rules" => [{
          "name" => "deep-rule",
          "type" => "blocklist",
          "condition" => inner
        }]
      })
      _(result.valid?).must_equal true
    end

    it "condition nested 21 levels deep is invalid with nesting error" do
      inner = { "field" => "ip.src", "operator" => "eq", "value" => "1.2.3.4" }
      21.times { inner = { "and" => [inner] } }

      result = validate({
        "rules" => [{
          "name" => "too-deep",
          "type" => "blocklist",
          "condition" => inner
        }]
      })
      _(result.valid?).must_equal false
      _(result.errors.any? { |e| e.include?("nesting too deep") }).must_equal true
    end
  end

  # --- Empty combinator arrays ---

  describe "empty combinator arrays" do
    it '{"and": []} is valid' do
      result = validate({
        "rules" => [{
          "name" => "empty-and",
          "type" => "blocklist",
          "condition" => { "and" => [] }
        }]
      })
      _(result.valid?).must_equal true
    end

    it '{"or": []} is valid' do
      result = validate({
        "rules" => [{
          "name" => "empty-or",
          "type" => "blocklist",
          "condition" => { "or" => [] }
        }]
      })
      _(result.valid?).must_equal true
    end
  end

  # --- Field edge cases ---

  describe "field validation edge cases" do
    it 'dynamic field with empty brackets is invalid' do
      result = validate({
        "rules" => [{
          "name" => "empty-brackets",
          "type" => "blocklist",
          "condition" => { "field" => 'http.request.headers[""]', "operator" => "eq", "value" => "x" }
        }]
      })
      _(result.valid?).must_equal false
      _(result.errors.any? { |e| e.include?("unknown field") }).must_equal true
    end

    it "condition with both 'and' and 'field' keys uses first key (and)" do
      result = validate({
        "rules" => [{
          "name" => "dual-key",
          "type" => "blocklist",
          "condition" => {
            "and" => [{ "field" => "ip.src", "operator" => "eq", "value" => "1.2.3.4" }],
            "field" => "ip.src"
          }
        }]
      })
      # "and" key is checked first, sub-conditions validated — should be valid
      _(result.valid?).must_equal true
    end
  end

  # --- Throttle validation ---

  describe "throttle-specific validation" do
    it "negative limit is invalid" do
      result = validate({
        "rules" => [{
          "name" => "neg-limit",
          "type" => "throttle",
          "condition" => { "field" => "ip.src", "operator" => "eq", "value" => "1.2.3.4" },
          "limit" => -5,
          "period" => 60
        }]
      })
      _(result.valid?).must_equal false
      _(result.errors.any? { |e| e.include?("positive numeric \"limit\"") }).must_equal true
    end

    it "negative period is invalid" do
      result = validate({
        "rules" => [{
          "name" => "neg-period",
          "type" => "throttle",
          "condition" => { "field" => "ip.src", "operator" => "eq", "value" => "1.2.3.4" },
          "limit" => 10,
          "period" => -30
        }]
      })
      _(result.valid?).must_equal false
      _(result.errors.any? { |e| e.include?("positive numeric \"period\"") }).must_equal true
    end
  end

  # --- Name validation ---

  describe "name validation" do
    it "empty name string is invalid" do
      result = validate({
        "rules" => [{
          "name" => "",
          "type" => "blocklist",
          "condition" => { "field" => "ip.src", "operator" => "eq", "value" => "1.2.3.4" }
        }]
      })
      _(result.valid?).must_equal false
      _(result.errors.any? { |e| e.include?("missing or empty \"name\"") }).must_equal true
    end

    it "non-string name (integer) is invalid" do
      result = validate({
        "rules" => [{
          "name" => 123,
          "type" => "blocklist",
          "condition" => { "field" => "ip.src", "operator" => "eq", "value" => "1.2.3.4" }
        }]
      })
      _(result.valid?).must_equal false
      _(result.errors.any? { |e| e.include?("missing or empty \"name\"") }).must_equal true
    end
  end

  # --- Non-Hash rule ---

  describe "non-Hash rule" do
    it "string instead of Hash in rules array is invalid" do
      result = validate({
        "rules" => ["not a hash"]
      })
      _(result.valid?).must_equal false
      _(result.errors.any? { |e| e.include?("must be a Hash") }).must_equal true
    end
  end

  # --- Non-Hash condition ---

  describe "non-Hash condition" do
    it "string instead of Hash as condition is invalid" do
      result = validate({
        "rules" => [{
          "name" => "bad-cond",
          "type" => "blocklist",
          "condition" => "not a hash"
        }]
      })
      _(result.valid?).must_equal false
      _(result.errors.any? { |e| e.include?("condition must be a Hash") }).must_equal true
    end
  end

  # --- or with non-array value ---

  describe "or with non-array" do
    it '"or" with string value is invalid' do
      result = validate({
        "rules" => [{
          "name" => "bad-or",
          "type" => "blocklist",
          "condition" => { "or" => "not-array" }
        }]
      })
      _(result.valid?).must_equal false
      _(result.errors.any? { |e| e.include?('"or" must be an Array') }).must_equal true
    end
  end

  # --- nil operator ---

  describe "nil operator" do
    it "nil operator in leaf condition is invalid" do
      result = validate({
        "rules" => [{
          "name" => "nil-op",
          "type" => "blocklist",
          "condition" => { "field" => "ip.src", "operator" => nil, "value" => "1.2.3.4" }
        }]
      })
      _(result.valid?).must_equal false
      _(result.errors.any? { |e| e.include?("invalid operator") }).must_equal true
    end
  end

  # --- Transform array with mix of valid/invalid ---

  describe "transform validation" do
    it "array with one invalid transform reports error" do
      result = validate({
        "rules" => [{
          "name" => "bad-transform",
          "type" => "blocklist",
          "condition" => { "field" => "ip.src", "operator" => "eq", "value" => "1.2.3.4", "transform" => ["lower", "invalid_t"] }
        }]
      })
      _(result.valid?).must_equal false
      _(result.errors.any? { |e| e.include?('invalid transform "invalid_t"') }).must_equal true
    end
  end

  # --- JWT key validation ---

  describe "jwt_keys validation" do
    it "non-Hash entry in jwt_keys is invalid" do
      result = validate({
        "rules" => [],
        "jwt_keys" => ["not-a-hash"]
      })
      _(result.valid?).must_equal false
      _(result.errors.any? { |e| e.include?("must be a Hash") }).must_equal true
    end

    it "empty algorithm string is invalid" do
      result = validate({
        "rules" => [],
        "jwt_keys" => [{ "algorithm" => "", "key" => "secret" }]
      })
      _(result.valid?).must_equal false
      _(result.errors.any? { |e| e.include?('missing or empty "algorithm"') }).must_equal true
    end

    it "empty key string is invalid" do
      result = validate({
        "rules" => [],
        "jwt_keys" => [{ "algorithm" => "HS256", "key" => "" }]
      })
      _(result.valid?).must_equal false
      _(result.errors.any? { |e| e.include?('missing or empty "key"') }).must_equal true
    end
  end

  # --- Throttle key field validation ---

  describe "throttle key field validation" do
    it "invalid key field name is reported" do
      result = validate({
        "rules" => [{
          "name" => "bad-key",
          "type" => "throttle",
          "condition" => { "field" => "ip.src", "operator" => "eq", "value" => "1.2.3.4" },
          "limit" => 10,
          "period" => 60,
          "key" => ["nonexistent.field"]
        }]
      })
      _(result.valid?).must_equal false
      _(result.errors.any? { |e| e.include?('invalid key field "nonexistent.field"') }).must_equal true
    end

    it "valid key field passes" do
      result = validate({
        "rules" => [{
          "name" => "good-key",
          "type" => "throttle",
          "condition" => { "field" => "ip.src", "operator" => "eq", "value" => "1.2.3.4" },
          "limit" => 10,
          "period" => 60,
          "key" => ["ip.src", 'http.request.headers["x-api-key"]']
        }]
      })
      _(result.valid?).must_equal true
    end
  end

  # --- CIDR format validation ---

  describe "CIDR format validation" do
    it "invalid CIDR in in_ip_range is reported" do
      result = validate({
        "rules" => [{
          "name" => "bad-cidr",
          "type" => "blocklist",
          "condition" => { "field" => "ip.src", "operator" => "in_ip_range", "value" => "not-a-cidr" }
        }]
      })
      _(result.valid?).must_equal false
      _(result.errors.any? { |e| e.include?('invalid CIDR "not-a-cidr"') }).must_equal true
    end

    it "valid CIDR passes" do
      result = validate({
        "rules" => [{
          "name" => "good-cidr",
          "type" => "blocklist",
          "condition" => { "field" => "ip.src", "operator" => "in_ip_range", "value" => ["10.0.0.0/8", "192.168.0.0/16"] }
        }]
      })
      _(result.valid?).must_equal true
    end
  end

  # --- Regex syntax validation ---

  describe "regex syntax validation" do
    it "invalid regex pattern is reported" do
      result = validate({
        "rules" => [{
          "name" => "bad-regex",
          "type" => "blocklist",
          "condition" => { "field" => "http.request.uri.path", "operator" => "matches", "value" => "[invalid" }
        }]
      })
      _(result.valid?).must_equal false
      _(result.errors.any? { |e| e.include?("invalid regex") }).must_equal true
    end

    it "valid regex passes" do
      result = validate({
        "rules" => [{
          "name" => "good-regex",
          "type" => "blocklist",
          "condition" => { "field" => "http.request.uri.path", "operator" => "matches", "value" => "^/api/v[0-9]+/" }
        }]
      })
      _(result.valid?).must_equal true
    end
  end

  # --- Numeric value validation ---

  describe "numeric value validation" do
    it "string value for gt operator is reported" do
      result = validate({
        "rules" => [{
          "name" => "bad-numeric",
          "type" => "blocklist",
          "condition" => { "field" => "http.request.body.size", "operator" => "gt", "value" => "not-a-number" }
        }]
      })
      _(result.valid?).must_equal false
      _(result.errors.any? { |e| e.include?("requires a numeric value") }).must_equal true
    end

    it "numeric value for gt passes" do
      result = validate({
        "rules" => [{
          "name" => "good-numeric",
          "type" => "blocklist",
          "condition" => { "field" => "http.request.body.size", "operator" => "gt", "value" => 1024 }
        }]
      })
      _(result.valid?).must_equal true
    end
  end

  # --- Duplicate rule names ---

  describe "duplicate rule names" do
    it "duplicate names are reported" do
      result = validate({
        "rules" => [
          { "name" => "dup-name", "type" => "blocklist", "condition" => { "field" => "ip.src", "operator" => "eq", "value" => "1.2.3.4" } },
          { "name" => "dup-name", "type" => "blocklist", "condition" => { "field" => "ip.src", "operator" => "eq", "value" => "5.6.7.8" } }
        ]
      })
      _(result.valid?).must_equal false
      _(result.errors.any? { |e| e.include?("duplicate rule name") }).must_equal true
    end

    it "unique names pass" do
      result = validate({
        "rules" => [
          { "name" => "rule-a", "type" => "blocklist", "condition" => { "field" => "ip.src", "operator" => "eq", "value" => "1.2.3.4" } },
          { "name" => "rule-b", "type" => "blocklist", "condition" => { "field" => "ip.src", "operator" => "eq", "value" => "5.6.7.8" } }
        ]
      })
      _(result.valid?).must_equal true
    end
  end

  # --- Extra top-level keys ---

  describe "extra top-level keys" do
    it "extra keys like metadata are allowed" do
      result = validate({
        "rules" => [{
          "name" => "test",
          "type" => "blocklist",
          "condition" => { "field" => "ip.src", "operator" => "eq", "value" => "1.2.3.4" }
        }],
        "metadata" => { "version" => "1.0" }
      })
      _(result.valid?).must_equal true
    end
  end
end
