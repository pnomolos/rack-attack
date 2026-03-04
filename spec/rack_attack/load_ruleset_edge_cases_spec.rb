# frozen_string_literal: true

require_relative "test_helper"
require "json"
require "tempfile"

describe "load_ruleset edge cases" do
  before do
    Rack::Attack.clear_configuration
  end

  after do
    Rack::Attack.clear_configuration
  end

  # --- Error handling ---

  describe "error handling" do
    it "invalid source type (integer) raises ArgumentError" do
      _(-> { Rack::Attack.load_ruleset(42) }).must_raise ArgumentError
    end

    it "malformed JSON string raises JSON::ParserError" do
      _(-> { Rack::Attack.load_ruleset("{invalid json") }).must_raise JSON::ParserError
    end

    it "non-existent .json file path falls through to JSON.parse which raises" do
      # A string ending in .json that doesn't exist as a file is treated as JSON string
      _(-> { Rack::Attack.load_ruleset("nonexistent.json") }).must_raise JSON::ParserError
    end
  end

  # --- Empty/duplicate ---

  describe "empty and duplicate rules" do
    it "empty rules array causes no crash and adds no rules" do
      Rack::Attack.load_ruleset({ "rules" => [] })

      result = Rack::Attack.simulate(ip: "1.2.3.4")
      _(result.outcome).must_equal :allow
    end

    it "duplicate rule names cause second to overwrite first" do
      Rack::Attack.load_ruleset({
        "rules" => [
          {
            "name" => "dup-rule",
            "type" => "blocklist",
            "condition" => { "field" => "ip.src", "operator" => "eq", "value" => "1.1.1.1" }
          },
          {
            "name" => "dup-rule",
            "type" => "blocklist",
            "condition" => { "field" => "ip.src", "operator" => "eq", "value" => "2.2.2.2" }
          }
        ]
      })

      # Second rule overwrites first — should match 2.2.2.2, not 1.1.1.1
      result = Rack::Attack.simulate(ip: "2.2.2.2")
      _(result.blocklisted?).must_equal true

      result = Rack::Attack.simulate(ip: "1.1.1.1")
      _(result.blocklisted?).must_equal false
    end
  end

  # --- JWT keys across loads ---

  describe "JWT keys across loads" do
    it "second load without jwt_keys sets @jwt_keys to nil" do
      Rack::Attack.load_ruleset({
        "rules" => [],
        "jwt_keys" => [{ "algorithm" => "HS256", "key" => "secret" }]
      })

      Rack::Attack.load_ruleset({ "rules" => [] })

      config = Rack::Attack.configuration
      _(config.instance_variable_get(:@jwt_keys)).must_be_nil
    end
  end

  # --- Unknown rule type ---

  describe "unknown rule type" do
    it "unknown rule type is silently ignored (no error, no rule registered)" do
      Rack::Attack.load_ruleset({
        "rules" => [{
          "name" => "unknown-type-rule",
          "type" => "unknown_type",
          "condition" => { "field" => "ip.src", "operator" => "eq", "value" => "1.2.3.4" }
        }]
      })

      # Should not crash, and the rule should not be registered as any type
      result = Rack::Attack.simulate(ip: "1.2.3.4")
      _(result.outcome).must_equal :allow
    end
  end

  # --- jwt_keys parameter override ---

  describe "jwt_keys parameter overrides embedded" do
    it "jwt_keys parameter takes precedence over embedded jwt_keys" do
      config = Rack::Attack.configuration

      Rack::Attack.load_ruleset(
        { "rules" => [], "jwt_keys" => [{ "algorithm" => "HS256", "key" => "embedded-secret" }] },
        jwt_keys: [{ "algorithm" => "HS384", "key" => "param-secret" }]
      )

      jwt_keys = config.instance_variable_get(:@jwt_keys)
      _(jwt_keys).wont_be_nil
      _(jwt_keys.first["algorithm"]).must_equal "HS384"
    end
  end

  # --- Replace mode ---

  describe "replace mode" do
    it "replace clears anonymous blocklists/safelists" do
      Rack::Attack.blocklist_ip("6.6.6.6")
      Rack::Attack.safelist_ip("10.0.0.0/8")

      Rack::Attack.load_ruleset({ "rules" => [] }, replace: true)

      _(Rack::Attack.configuration.anonymous_blocklists).must_be_empty
      _(Rack::Attack.configuration.anonymous_safelists).must_be_empty
    end

    it "replace clears @json_rules and @json_rule_names" do
      Rack::Attack.load_ruleset({
        "rules" => [{
          "name" => "old-rule",
          "type" => "blocklist",
          "condition" => { "field" => "ip.src", "operator" => "eq", "value" => "1.1.1.1" }
        }]
      })

      Rack::Attack.load_ruleset({ "rules" => [] }, replace: true)

      config = Rack::Attack.configuration
      _(config.instance_variable_get(:@json_rules)).must_be_empty
      _(config.instance_variable_get(:@json_rule_names)).must_be_empty
    end

    it "replace with empty rules results in clean state" do
      Rack::Attack.blocklist("named-block") { |req| req.ip == "6.6.6.6" }
      Rack::Attack.throttle("rate-limit", limit: 10, period: 60) { |req| req.ip }

      Rack::Attack.load_ruleset({ "rules" => [] }, replace: true)

      result = Rack::Attack.simulate(ip: "6.6.6.6")
      _(result.outcome).must_equal :allow
    end
  end
end
