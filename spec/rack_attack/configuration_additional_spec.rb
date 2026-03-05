# frozen_string_literal: true

require_relative "test_helper"
require "json"
require "stringio"

describe "Configuration additional tests" do
  before do
    Rack::Attack.clear_configuration
    Rack::Attack.cache.store = ActiveSupport::Cache::MemoryStore.new
  end

  after do
    Rack::Attack.clear_configuration
    Rack::Attack.instance_variable_set(:@cache, nil)
  end

  def make_request(env = {})
    defaults = {
      "REQUEST_METHOD" => "GET",
      "PATH_INFO" => "/",
      "QUERY_STRING" => "",
      "REMOTE_ADDR" => "1.2.3.4",
      "HTTP_HOST" => "example.com",
      "rack.input" => StringIO.new(""),
      "SERVER_NAME" => "example.com",
      "SERVER_PORT" => "80"
    }
    Rack::Attack::Request.new(defaults.merge(env))
  end

  # ===========================================================================
  # load_ruleset with validate: true
  # ===========================================================================

  describe "load_ruleset with validate: true" do
    it "raises ArgumentError for missing rules array" do
      _(-> {
        Rack::Attack.load_ruleset({ "other" => "data" }, validate: true)
      }).must_raise ArgumentError
    end

    it "raises ArgumentError for invalid rule type" do
      # Use a rule without a name to avoid the validator's duplicate-name bug
      _(-> {
        Rack::Attack.load_ruleset({
          "rules" => [{ "type" => "invalid_type" }]
        }, validate: true)
      }).must_raise ArgumentError
    end

    it "raises ArgumentError for throttle missing limit" do
      _(-> {
        Rack::Attack.load_ruleset({
          "rules" => [{
            "name" => "bad-throttle",
            "type" => "throttle",
            "period" => 60,
            "condition" => { "field" => "ip.src", "operator" => "eq", "value" => "1.1.1.1" }
          }]
        }, validate: true)
      }).must_raise ArgumentError
    end

    it "raises ArgumentError for unknown field in condition" do
      _(-> {
        Rack::Attack.load_ruleset({
          "rules" => [{
            "name" => "bad-field",
            "type" => "blocklist",
            "condition" => { "field" => "unknown.field", "operator" => "eq", "value" => "x" }
          }]
        }, validate: true)
      }).must_raise ArgumentError
    end

    it "raises ArgumentError for invalid regex pattern" do
      _(-> {
        Rack::Attack.load_ruleset({
          "rules" => [{
            "name" => "bad-regex",
            "type" => "blocklist",
            "condition" => { "field" => "http.request.uri.path", "operator" => "matches", "value" => "[invalid" }
          }]
        }, validate: true)
      }).must_raise ArgumentError
    end

    it "raises ArgumentError for invalid CIDR" do
      _(-> {
        Rack::Attack.load_ruleset({
          "rules" => [{
            "name" => "bad-cidr",
            "type" => "blocklist",
            "condition" => { "field" => "ip.src", "operator" => "in_ip_range", "value" => ["not-a-cidr"] }
          }]
        }, validate: true)
      }).must_raise ArgumentError
    end

    it "succeeds for valid ruleset with validate: true" do
      Rack::Attack.load_ruleset({
        "rules" => [{
          "name" => "valid-rule",
          "type" => "blocklist",
          "condition" => { "field" => "ip.src", "operator" => "eq", "value" => "6.6.6.6" }
        }]
      }, validate: true)

      config = Rack::Attack.configuration
      _(config.blocklists).must_include "valid-rule"
    end

    it "includes error details in the exception message" do
      err = assert_raises(ArgumentError) do
        Rack::Attack.load_ruleset({ "other" => "data" }, validate: true)
      end
      _(err.message).must_include "Invalid ruleset"
      _(err.message).must_include "rules"
    end
  end

  # ===========================================================================
  # clear_configuration resets all state
  # ===========================================================================

  describe "clear_configuration resets all state" do
    it "resets json_rules to empty" do
      Rack::Attack.load_ruleset({
        "rules" => [{
          "name" => "test-rule",
          "type" => "blocklist",
          "condition" => { "field" => "ip.src", "operator" => "eq", "value" => "1.1.1.1" }
        }]
      })

      config = Rack::Attack.configuration
      _(config.instance_variable_get(:@json_rules)).wont_be_empty

      Rack::Attack.clear_configuration
      config = Rack::Attack.configuration
      _(config.instance_variable_get(:@json_rules)).must_be_empty
    end

    it "resets jwt_keys to nil" do
      Rack::Attack.load_ruleset({
        "rules" => [],
        "jwt_keys" => [{ "algorithm" => "HS256", "key" => "secret" }]
      })

      config = Rack::Attack.configuration
      _(config.instance_variable_get(:@jwt_keys)).wont_be_nil

      Rack::Attack.clear_configuration
      config = Rack::Attack.configuration
      _(config.instance_variable_get(:@jwt_keys)).must_be_nil
    end

    it "resets native_ruleset to nil" do
      Rack::Attack.load_ruleset({
        "rules" => [{
          "name" => "test",
          "type" => "blocklist",
          "condition" => { "field" => "ip.src", "operator" => "eq", "value" => "1.1.1.1" }
        }]
      })

      Rack::Attack.clear_configuration
      config = Rack::Attack.configuration
      _(config.instance_variable_get(:@native_ruleset)).must_be_nil
    end

    it "resets rule_order to nil" do
      Rack::Attack.load_ruleset({
        "rule_order" => "cost",
        "rules" => []
      })

      config = Rack::Attack.configuration
      _(config.instance_variable_get(:@rule_order)).must_equal "cost"

      Rack::Attack.clear_configuration
      config = Rack::Attack.configuration
      _(config.instance_variable_get(:@rule_order)).must_be_nil
    end

    it "resets all named rule collections" do
      Rack::Attack.load_ruleset({
        "rules" => [
          { "name" => "sl", "type" => "safelist",
            "condition" => { "field" => "ip.src", "operator" => "eq", "value" => "1.1.1.1" } },
          { "name" => "bl", "type" => "blocklist",
            "condition" => { "field" => "ip.src", "operator" => "eq", "value" => "2.2.2.2" } },
          { "name" => "th", "type" => "throttle", "limit" => 10, "period" => 60,
            "key" => ["ip.src"],
            "condition" => { "field" => "ip.src", "operator" => "eq", "value" => "3.3.3.3" } },
          { "name" => "tr", "type" => "track",
            "condition" => { "field" => "ip.src", "operator" => "eq", "value" => "4.4.4.4" } }
        ]
      })

      Rack::Attack.clear_configuration
      config = Rack::Attack.configuration
      _(config.safelists).must_be_empty
      _(config.blocklists).must_be_empty
      _(config.throttles).must_be_empty
      _(config.tracks).must_be_empty
    end

    it "resets anonymous blocklists and safelists" do
      Rack::Attack.blocklist_ip("6.6.6.6")
      Rack::Attack.safelist_ip("10.0.0.0/8")

      Rack::Attack.clear_configuration
      config = Rack::Attack.configuration
      _(config.anonymous_blocklists).must_be_empty
      _(config.anonymous_safelists).must_be_empty
    end
  end

  # ===========================================================================
  # Duplicate rule names (second overwrites first)
  # ===========================================================================

  describe "duplicate rule names" do
    it "second rule with same name overwrites the first in blocklists" do
      Rack::Attack.load_ruleset({
        "rules" => [
          { "name" => "dup-block", "type" => "blocklist",
            "condition" => { "field" => "ip.src", "operator" => "eq", "value" => "1.1.1.1" } },
          { "name" => "dup-block", "type" => "blocklist",
            "condition" => { "field" => "ip.src", "operator" => "eq", "value" => "2.2.2.2" } }
        ]
      })

      config = Rack::Attack.configuration

      # The second rule's condition should be active (overwrites)
      request = make_request("REMOTE_ADDR" => "2.2.2.2")
      _(config.blocklisted?(request)).must_equal true

      # The first rule's condition should not match anymore
      request = make_request("REMOTE_ADDR" => "1.1.1.1")
      _(config.blocklisted?(request)).must_equal false
    end

    it "second rule with same name overwrites in safelists" do
      Rack::Attack.load_ruleset({
        "rules" => [
          { "name" => "dup-safe", "type" => "safelist",
            "condition" => { "field" => "http.request.uri.path", "operator" => "eq", "value" => "/healthz" } },
          { "name" => "dup-safe", "type" => "safelist",
            "condition" => { "field" => "http.request.uri.path", "operator" => "eq", "value" => "/readiness" } }
        ]
      })

      config = Rack::Attack.configuration

      request = make_request("PATH_INFO" => "/readiness")
      _(config.safelisted?(request)).must_equal true

      request = make_request("PATH_INFO" => "/healthz")
      _(config.safelisted?(request)).must_equal false
    end
  end

  # ===========================================================================
  # Multiple load_ruleset calls accumulate rules
  # ===========================================================================

  describe "multiple load_ruleset calls" do
    it "accumulates rules from successive calls" do
      Rack::Attack.load_ruleset({
        "rules" => [
          { "name" => "block-1", "type" => "blocklist",
            "condition" => { "field" => "ip.src", "operator" => "eq", "value" => "1.1.1.1" } }
        ]
      })

      Rack::Attack.load_ruleset({
        "rules" => [
          { "name" => "block-2", "type" => "blocklist",
            "condition" => { "field" => "ip.src", "operator" => "eq", "value" => "2.2.2.2" } }
        ]
      })

      config = Rack::Attack.configuration
      _(config.blocklists).must_include "block-1"
      _(config.blocklists).must_include "block-2"

      # Both rules should work
      request = make_request("REMOTE_ADDR" => "1.1.1.1")
      _(config.blocklisted?(request)).must_equal true

      request = make_request("REMOTE_ADDR" => "2.2.2.2")
      _(config.blocklisted?(request)).must_equal true
    end

    it "accumulates rules of different types" do
      Rack::Attack.load_ruleset({
        "rules" => [
          { "name" => "safe-health", "type" => "safelist",
            "condition" => { "field" => "http.request.uri.path", "operator" => "eq", "value" => "/healthz" } }
        ]
      })

      Rack::Attack.load_ruleset({
        "rules" => [
          { "name" => "block-bad-ip", "type" => "blocklist",
            "condition" => { "field" => "ip.src", "operator" => "eq", "value" => "6.6.6.6" } }
        ]
      })

      Rack::Attack.load_ruleset({
        "rules" => [
          { "name" => "track-api", "type" => "track",
            "condition" => { "field" => "http.request.uri.path", "operator" => "starts_with", "value" => "/api/" } }
        ]
      })

      config = Rack::Attack.configuration
      _(config.safelists).must_include "safe-health"
      _(config.blocklists).must_include "block-bad-ip"
      _(config.tracks).must_include "track-api"
    end

    it "json_rules accumulates entries" do
      Rack::Attack.load_ruleset({
        "rules" => [
          { "name" => "r1", "type" => "blocklist",
            "condition" => { "field" => "ip.src", "operator" => "eq", "value" => "1.1.1.1" } }
        ]
      })
      Rack::Attack.load_ruleset({
        "rules" => [
          { "name" => "r2", "type" => "blocklist",
            "condition" => { "field" => "ip.src", "operator" => "eq", "value" => "2.2.2.2" } }
        ]
      })

      config = Rack::Attack.configuration
      json_rules = config.instance_variable_get(:@json_rules)
      _(json_rules.length).must_equal 2
    end
  end

  # ===========================================================================
  # jwt_keys persistence across calls
  # ===========================================================================

  describe "jwt_keys persistence across load_ruleset calls" do
    it "jwt_keys persists when second load has no jwt_keys" do
      Rack::Attack.load_ruleset({
        "rules" => [],
        "jwt_keys" => [{ "algorithm" => "HS256", "key" => "secret" }]
      })

      # Second load without jwt_keys — keys should persist
      Rack::Attack.load_ruleset({
        "rules" => [
          { "name" => "block-1", "type" => "blocklist",
            "condition" => { "field" => "ip.src", "operator" => "eq", "value" => "1.1.1.1" } }
        ]
      })

      config = Rack::Attack.configuration
      jwt_keys = config.instance_variable_get(:@jwt_keys)
      _(jwt_keys).wont_be_nil
      _(jwt_keys.first["algorithm"]).must_equal "HS256"
    end

    it "jwt_keys is replaced when second load provides new jwt_keys" do
      Rack::Attack.load_ruleset({
        "rules" => [],
        "jwt_keys" => [{ "algorithm" => "HS256", "key" => "old-secret" }]
      })

      Rack::Attack.load_ruleset({
        "rules" => [],
        "jwt_keys" => [{ "algorithm" => "RS256", "key" => "new-key-pem" }]
      })

      config = Rack::Attack.configuration
      jwt_keys = config.instance_variable_get(:@jwt_keys)
      _(jwt_keys.first["algorithm"]).must_equal "RS256"
    end

    it "jwt_keys parameter overrides embedded jwt_keys in data" do
      Rack::Attack.load_ruleset(
        { "rules" => [], "jwt_keys" => [{ "algorithm" => "HS256", "key" => "embedded" }] },
        jwt_keys: [{ "algorithm" => "HS384", "key" => "param-key" }]
      )

      config = Rack::Attack.configuration
      jwt_keys = config.instance_variable_get(:@jwt_keys)
      _(jwt_keys.first["algorithm"]).must_equal "HS384"
    end
  end

  # ===========================================================================
  # Disabled rules
  # ===========================================================================

  describe "disabled rules" do
    it "rules with enabled: false are not registered" do
      Rack::Attack.load_ruleset({
        "rules" => [{
          "name" => "disabled-rule",
          "type" => "blocklist",
          "enabled" => false,
          "condition" => { "field" => "ip.src", "operator" => "eq", "value" => "1.1.1.1" }
        }]
      })

      config = Rack::Attack.configuration
      _(config.blocklists).wont_include "disabled-rule"
    end

    it "enabled: true rules are registered normally" do
      Rack::Attack.load_ruleset({
        "rules" => [{
          "name" => "enabled-rule",
          "type" => "blocklist",
          "enabled" => true,
          "condition" => { "field" => "ip.src", "operator" => "eq", "value" => "1.1.1.1" }
        }]
      })

      config = Rack::Attack.configuration
      _(config.blocklists).must_include "enabled-rule"
    end
  end
end
