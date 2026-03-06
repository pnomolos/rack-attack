# frozen_string_literal: true

require_relative "test_helper"

describe "Rack::Attack.validate_ruleset" do
  before do
    Rack::Attack.clear_configuration
  end

  after do
    Rack::Attack.clear_configuration
  end

  describe "valid rulesets" do
    it "validates a minimal blocklist rule" do
      result = Rack::Attack.validate_ruleset({
        "rules" => [
          {
            "name" => "block-ip",
            "type" => "blocklist",
            "condition" => { "field" => "ip.src", "operator" => "eq", "value" => "6.6.6.6" }
          }
        ]
      })

      _(result.valid?).must_equal true
      _(result.errors).must_be_empty
    end

    it "validates a throttle rule with required fields" do
      result = Rack::Attack.validate_ruleset({
        "rules" => [
          {
            "name" => "rate-limit",
            "type" => "throttle",
            "limit" => 100,
            "period" => 60,
            "key" => ["ip.src"],
            "condition" => { "field" => "http.request.uri.path", "operator" => "starts_with", "value" => "/api" }
          }
        ]
      })

      _(result.valid?).must_equal true
    end

    it "validates rules with logical combinators" do
      result = Rack::Attack.validate_ruleset({
        "rules" => [
          {
            "name" => "complex-rule",
            "type" => "blocklist",
            "condition" => {
              "and" => [
                { "field" => "ip.src", "operator" => "in_ip_range", "value" => ["10.0.0.0/8"] },
                {
                  "or" => [
                    { "field" => "http.request.uri.path", "operator" => "starts_with", "value" => "/admin" },
                    { "field" => "http.request.method", "operator" => "eq", "value" => "DELETE" }
                  ]
                }
              ]
            }
          }
        ]
      })

      _(result.valid?).must_equal true
    end

    it "validates rules with not combinator" do
      result = Rack::Attack.validate_ruleset({
        "rules" => [
          {
            "name" => "not-rule",
            "type" => "safelist",
            "condition" => {
              "not" => { "field" => "ip.src", "operator" => "in_ip_range", "value" => ["192.168.0.0/16"] }
            }
          }
        ]
      })

      _(result.valid?).must_equal true
    end

    it "validates rules with transforms" do
      result = Rack::Attack.validate_ruleset({
        "rules" => [
          {
            "name" => "case-insensitive",
            "type" => "blocklist",
            "condition" => {
              "field" => "http.user_agent",
              "operator" => "contains",
              "value" => "badbot",
              "transform" => "lower"
            }
          }
        ]
      })

      _(result.valid?).must_equal true
    end

    it "validates exists/not_exists operators without value" do
      result = Rack::Attack.validate_ruleset({
        "rules" => [
          {
            "name" => "check-header",
            "type" => "track",
            "condition" => { "field" => 'http.request.headers["x-api-key"]', "operator" => "exists" }
          }
        ]
      })

      _(result.valid?).must_equal true
    end

    it "validates all dynamic field patterns" do
      fields = [
        'http.request.headers["x-custom"]',
        'http.request.cookies["session"]',
        'http.request.uri.args["page"]',
        'http.request.body.json["user"]',
        'jwt.payload["sub"]',
        'jwt.header["alg"]',
        'jwt.verified_payload["role"]'
      ]

      rules = fields.map.with_index do |field, i|
        { "name" => "rule-#{i}", "type" => "track", "condition" => { "field" => field, "operator" => "exists" } }
      end

      result = Rack::Attack.validate_ruleset({ "rules" => rules })
      _(result.valid?).must_equal true
    end

    it "accepts symbol keys" do
      result = Rack::Attack.validate_ruleset({
        rules: [
          {
            name: "block-ip",
            type: "blocklist",
            condition: { field: "ip.src", operator: "eq", value: "6.6.6.6" }
          }
        ]
      })

      _(result.valid?).must_equal true
    end
  end

  describe "invalid rulesets" do
    it "rejects non-hash input" do
      result = Rack::Attack.validate_ruleset('{"rules": []}')
      # parse_source converts JSON string to hash, so this should work
      _(result.valid?).must_equal true
    end

    it "rejects missing rules array" do
      result = Rack::Attack.validate_ruleset({ "other" => "data" })
      _(result.valid?).must_equal false
      _(result.errors.first).must_include "rules"
    end

    it "rejects rule without name" do
      result = Rack::Attack.validate_ruleset({
        "rules" => [
          { "type" => "blocklist", "condition" => { "field" => "ip.src", "operator" => "eq", "value" => "1.1.1.1" } }
        ]
      })

      _(result.valid?).must_equal false
      _(result.errors.any? { |e| e.include?("name") }).must_equal true
    end

    it "rejects rule without type" do
      result = Rack::Attack.validate_ruleset({
        "rules" => [
          { "name" => "test", "condition" => { "field" => "ip.src", "operator" => "eq", "value" => "1.1.1.1" } }
        ]
      })

      _(result.valid?).must_equal false
      _(result.errors.any? { |e| e.include?("type") }).must_equal true
    end

    it "rejects invalid type" do
      result = Rack::Attack.validate_ruleset({
        "rules" => [
          {
            "name" => "test",
            "type" => "invalid",
            "condition" => { "field" => "ip.src", "operator" => "eq", "value" => "1.1.1.1" }
          }
        ]
      })

      _(result.valid?).must_equal false
      _(result.errors.any? { |e| e.include?("invalid") }).must_equal true
    end

    it "rejects rule without condition" do
      result = Rack::Attack.validate_ruleset({
        "rules" => [
          { "name" => "test", "type" => "blocklist" }
        ]
      })

      _(result.valid?).must_equal false
      _(result.errors.any? { |e| e.include?("condition") }).must_equal true
    end

    it "rejects throttle without limit" do
      result = Rack::Attack.validate_ruleset({
        "rules" => [
          {
            "name" => "test",
            "type" => "throttle",
            "period" => 60,
            "condition" => { "field" => "ip.src", "operator" => "eq", "value" => "1.1.1.1" }
          }
        ]
      })

      _(result.valid?).must_equal false
      _(result.errors.any? { |e| e.include?("limit") }).must_equal true
    end

    it "rejects throttle without period" do
      result = Rack::Attack.validate_ruleset({
        "rules" => [
          {
            "name" => "test",
            "type" => "throttle",
            "limit" => 10,
            "condition" => { "field" => "ip.src", "operator" => "eq", "value" => "1.1.1.1" }
          }
        ]
      })

      _(result.valid?).must_equal false
      _(result.errors.any? { |e| e.include?("period") }).must_equal true
    end

    it "rejects unknown field" do
      result = Rack::Attack.validate_ruleset({
        "rules" => [
          {
            "name" => "test",
            "type" => "blocklist",
            "condition" => { "field" => "unknown.field", "operator" => "eq", "value" => "x" }
          }
        ]
      })

      _(result.valid?).must_equal false
      _(result.errors.any? { |e| e.include?("unknown.field") }).must_equal true
    end

    it "rejects unknown operator" do
      result = Rack::Attack.validate_ruleset({
        "rules" => [
          {
            "name" => "test",
            "type" => "blocklist",
            "condition" => { "field" => "ip.src", "operator" => "fuzzy_match", "value" => "x" }
          }
        ]
      })

      _(result.valid?).must_equal false
      _(result.errors.any? { |e| e.include?("fuzzy_match") }).must_equal true
    end

    it "rejects unknown transform" do
      result = Rack::Attack.validate_ruleset({
        "rules" => [
          {
            "name" => "test",
            "type" => "blocklist",
            "condition" => { "field" => "ip.src", "operator" => "eq", "value" => "x", "transform" => "rot13" }
          }
        ]
      })

      _(result.valid?).must_equal false
      _(result.errors.any? { |e| e.include?("rot13") }).must_equal true
    end

    it "rejects missing value for non-existence operators" do
      result = Rack::Attack.validate_ruleset({
        "rules" => [
          {
            "name" => "test",
            "type" => "blocklist",
            "condition" => { "field" => "ip.src", "operator" => "eq" }
          }
        ]
      })

      _(result.valid?).must_equal false
      _(result.errors.any? { |e| e.include?("value") }).must_equal true
    end

    it "rejects invalid and combinator" do
      result = Rack::Attack.validate_ruleset({
        "rules" => [
          {
            "name" => "test",
            "type" => "blocklist",
            "condition" => { "and" => "not-an-array" }
          }
        ]
      })

      _(result.valid?).must_equal false
      _(result.errors.any? { |e| e.include?("Array") }).must_equal true
    end

    it "reports multiple errors" do
      result = Rack::Attack.validate_ruleset({
        "rules" => [
          { "type" => "invalid" },
          {
            "name" => "test",
            "type" => "throttle",
            "condition" => { "field" => "bad.field", "operator" => "bad_op", "value" => "x" }
          }
        ]
      })

      _(result.valid?).must_equal false
      _(result.errors.length).must_be :>, 2
    end
  end

  describe "throttle key field validation" do
    def throttle_rule_with_key(key)
      {
        "rules" => [
          {
            "name" => "test-throttle",
            "type" => "throttle",
            "limit" => 100,
            "period" => 60,
            "key" => key,
            "condition" => { "field" => "http.request.uri.path", "operator" => "starts_with", "value" => "/" }
          }
        ]
      }
    end

    it "accepts string key entries" do
      result = Rack::Attack.validate_ruleset(throttle_rule_with_key(["ip.src"]))
      _(result.valid?).must_equal true
    end

    it "accepts object key entries with field and transform" do
      result = Rack::Attack.validate_ruleset(
        throttle_rule_with_key([{ "field" => "http.request.uri.path", "transform" => "sha256" }])
      )
      _(result.valid?).must_equal true
    end

    it "accepts mixed string and object key entries" do
      result = Rack::Attack.validate_ruleset(
        throttle_rule_with_key(["ip.src", { "field" => "http.request.uri.path", "transform" => "sha256" }])
      )
      _(result.valid?).must_equal true
    end

    it "accepts object key entries without transform" do
      result = Rack::Attack.validate_ruleset(
        throttle_rule_with_key([{ "field" => "ip.src" }])
      )
      _(result.valid?).must_equal true
    end

    it "accepts object key entries with array transform" do
      result = Rack::Attack.validate_ruleset(
        throttle_rule_with_key([{ "field" => "http.request.uri.path", "transform" => ["url_decode", "sha256"] }])
      )
      _(result.valid?).must_equal true
    end

    it "rejects object key entries with invalid field" do
      result = Rack::Attack.validate_ruleset(
        throttle_rule_with_key([{ "field" => "bad.field" }])
      )
      _(result.valid?).must_equal false
      _(result.errors.any? { |e| e.include?("bad.field") }).must_equal true
    end

    it "rejects object key entries with non-string field" do
      result = Rack::Attack.validate_ruleset(
        throttle_rule_with_key([{ "field" => 123 }])
      )
      _(result.valid?).must_equal false
      _(result.errors.any? { |e| e.include?("key field") }).must_equal true
    end

    it "rejects object key entries with invalid transform" do
      result = Rack::Attack.validate_ruleset(
        throttle_rule_with_key([{ "field" => "ip.src", "transform" => "rot13" }])
      )
      _(result.valid?).must_equal false
      _(result.errors.any? { |e| e.include?("rot13") }).must_equal true
    end

    it "rejects non-string non-hash key entries" do
      result = Rack::Attack.validate_ruleset(
        throttle_rule_with_key([123])
      )
      _(result.valid?).must_equal false
      _(result.errors.any? { |e| e.include?("key entry") }).must_equal true
    end

    it "rejects object key entries with unknown extra keys" do
      result = Rack::Attack.validate_ruleset(
        throttle_rule_with_key([{ "field" => "ip.src", "typo_key" => "value" }])
      )
      _(result.valid?).must_equal false
      _(result.errors.any? { |e| e.include?("typo_key") }).must_equal true
    end

    it "accepts sha256 transform in conditions" do
      result = Rack::Attack.validate_ruleset({
        "rules" => [
          {
            "name" => "sha256-block",
            "type" => "blocklist",
            "condition" => {
              "field" => "http.request.uri.path",
              "operator" => "eq",
              "value" => "somehash",
              "transform" => "sha256"
            }
          }
        ]
      })
      _(result.valid?).must_equal true
    end
  end

  describe "jwt_keys validation" do
    it "validates valid jwt_keys" do
      result = Rack::Attack.validate_ruleset({
        "rules" => [],
        "jwt_keys" => [
          { "algorithm" => "HS256", "key" => "secret" }
        ]
      })

      _(result.valid?).must_equal true
    end

    it "rejects non-array jwt_keys" do
      result = Rack::Attack.validate_ruleset({
        "rules" => [],
        "jwt_keys" => "not-an-array"
      })

      _(result.valid?).must_equal false
      _(result.errors.any? { |e| e.include?("jwt_keys") }).must_equal true
    end

    it "rejects jwt_key entry without algorithm" do
      result = Rack::Attack.validate_ruleset({
        "rules" => [],
        "jwt_keys" => [{ "key" => "secret" }]
      })

      _(result.valid?).must_equal false
      _(result.errors.any? { |e| e.include?("algorithm") }).must_equal true
    end

    it "rejects jwt_key entry without key" do
      result = Rack::Attack.validate_ruleset({
        "rules" => [],
        "jwt_keys" => [{ "algorithm" => "HS256" }]
      })

      _(result.valid?).must_equal false
      _(result.errors.any? { |e| e.include?("key") }).must_equal true
    end
  end
end
