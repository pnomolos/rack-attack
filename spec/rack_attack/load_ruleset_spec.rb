# frozen_string_literal: true

require_relative "../spec_helper"
require "json"
require "stringio"
require "tmpdir"

describe "Rack::Attack.load_ruleset" do
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
      "rack.input" => StringIO.new("")
    }
    Rack::Attack::Request.new(defaults.merge(env))
  end

  describe "input formats" do
    it "accepts a Ruby Hash" do
      Rack::Attack.load_ruleset({
        "rules" => [
          { "name" => "block-test", "type" => "blocklist",
            "condition" => { "field" => "ip.src", "operator" => "eq", "value" => "6.6.6.6" } }
        ]
      })

      config = Rack::Attack.configuration
      _(config.blocklists).must_include "block-test"
    end

    it "accepts a Hash with symbol keys" do
      Rack::Attack.load_ruleset({
        rules: [
          { name: "block-sym", type: "blocklist",
            condition: { field: "ip.src", operator: "eq", value: "6.6.6.6" } }
        ]
      })

      config = Rack::Attack.configuration
      _(config.blocklists).must_include "block-sym"
    end

    it "accepts a JSON string" do
      json = JSON.generate({
        "rules" => [
          { "name" => "block-json", "type" => "blocklist",
            "condition" => { "field" => "ip.src", "operator" => "eq", "value" => "6.6.6.6" } }
        ]
      })

      Rack::Attack.load_ruleset(json)
      config = Rack::Attack.configuration
      _(config.blocklists).must_include "block-json"
    end

    it "accepts a file path" do
      Dir.mktmpdir do |dir|
        path = File.join(dir, "rules.json")
        File.write(path, JSON.generate({
          "rules" => [
            { "name" => "block-file", "type" => "blocklist",
              "condition" => { "field" => "ip.src", "operator" => "eq", "value" => "6.6.6.6" } }
          ]
        }))

        Rack::Attack.load_ruleset(path)
        config = Rack::Attack.configuration
        _(config.blocklists).must_include "block-file"
      end
    end
  end

  describe "rule types" do
    it "creates safelists" do
      Rack::Attack.load_ruleset({
        "rules" => [
          { "name" => "health-check", "type" => "safelist",
            "condition" => { "field" => "http.request.uri.path", "operator" => "eq", "value" => "/healthz" } }
        ]
      })

      config = Rack::Attack.configuration
      _(config.safelists).must_include "health-check"

      request = make_request("PATH_INFO" => "/healthz")
      _(config.safelisted?(request)).must_equal true

      request = make_request("PATH_INFO" => "/api")
      _(config.safelisted?(request)).must_equal false
    end

    it "creates blocklists" do
      Rack::Attack.load_ruleset({
        "rules" => [
          { "name" => "bad-ip", "type" => "blocklist",
            "condition" => { "field" => "ip.src", "operator" => "eq", "value" => "6.6.6.6" } }
        ]
      })

      config = Rack::Attack.configuration
      request = make_request("REMOTE_ADDR" => "6.6.6.6")
      _(config.blocklisted?(request)).must_equal true

      request = make_request("REMOTE_ADDR" => "1.2.3.4")
      _(config.blocklisted?(request)).must_equal false
    end

    it "creates throttles" do
      Rack::Attack.load_ruleset({
        "rules" => [
          { "name" => "api/ip", "type" => "throttle", "limit" => 2, "period" => 60,
            "key" => ["ip.src"],
            "condition" => { "field" => "http.request.uri.path", "operator" => "starts_with", "value" => "/api/" } }
        ]
      })

      config = Rack::Attack.configuration
      _(config.throttles).must_include "api/ip"

      # First requests should not be throttled
      request = make_request("PATH_INFO" => "/api/users", "REMOTE_ADDR" => "1.2.3.4")
      _(config.throttled?(request)).must_equal false

      # Non-matching path should not be throttled
      request = make_request("PATH_INFO" => "/other", "REMOTE_ADDR" => "1.2.3.4")
      _(config.throttled?(request)).must_equal false
    end

    it "creates tracks" do
      Rack::Attack.load_ruleset({
        "rules" => [
          { "name" => "api-version", "type" => "track",
            "condition" => { "field" => "http.request.uri.path", "operator" => "starts_with", "value" => "/api/" } }
        ]
      })

      config = Rack::Attack.configuration
      _(config.tracks).must_include "api-version"
    end

    it "creates throttle with null condition (always matches)" do
      Rack::Attack.load_ruleset({
        "rules" => [
          { "name" => "global/ip", "type" => "throttle", "limit" => 100, "period" => 60,
            "key" => ["ip.src"], "condition" => nil }
        ]
      })

      config = Rack::Attack.configuration
      _(config.throttles).must_include "global/ip"

      # Should match any request
      request = make_request("PATH_INFO" => "/anything")
      _(config.throttled?(request)).must_equal false # First request, under limit
    end
  end

  describe "replace mode" do
    it "clears existing rules when replace: true" do
      Rack::Attack.blocklist("existing-block") { |_req| false }
      _(Rack::Attack.configuration.blocklists).must_include "existing-block"

      Rack::Attack.load_ruleset({
        "rules" => [
          { "name" => "new-block", "type" => "blocklist",
            "condition" => { "field" => "ip.src", "operator" => "eq", "value" => "6.6.6.6" } }
        ]
      }, replace: true)

      config = Rack::Attack.configuration
      _(config.blocklists).wont_include "existing-block"
      _(config.blocklists).must_include "new-block"
    end

    it "appends to existing rules by default" do
      Rack::Attack.blocklist("existing-block") { |_req| false }

      Rack::Attack.load_ruleset({
        "rules" => [
          { "name" => "new-block", "type" => "blocklist",
            "condition" => { "field" => "ip.src", "operator" => "eq", "value" => "6.6.6.6" } }
        ]
      })

      config = Rack::Attack.configuration
      _(config.blocklists).must_include "existing-block"
      _(config.blocklists).must_include "new-block"
    end
  end

  describe "interaction with block-based rules" do
    it "block rules work alongside JSON rules" do
      Rack::Attack.blocklist("block-dsl") { |req| req.ip == "9.9.9.9" }

      Rack::Attack.load_ruleset({
        "rules" => [
          { "name" => "block-json", "type" => "blocklist",
            "condition" => { "field" => "ip.src", "operator" => "eq", "value" => "6.6.6.6" } }
        ]
      })

      config = Rack::Attack.configuration

      # JSON rule blocks
      request = make_request("REMOTE_ADDR" => "6.6.6.6")
      _(config.blocklisted?(request)).must_equal true

      # Block DSL rule blocks
      request = make_request("REMOTE_ADDR" => "9.9.9.9")
      _(config.blocklisted?(request)).must_equal true

      # Neither blocks
      request = make_request("REMOTE_ADDR" => "1.2.3.4")
      _(config.blocklisted?(request)).must_equal false
    end
  end

  describe "multiple loads" do
    it "appends rules from multiple loads" do
      Rack::Attack.load_ruleset({
        "rules" => [
          { "name" => "block-1", "type" => "blocklist",
            "condition" => { "field" => "ip.src", "operator" => "eq", "value" => "6.6.6.6" } }
        ]
      })

      Rack::Attack.load_ruleset({
        "rules" => [
          { "name" => "block-2", "type" => "blocklist",
            "condition" => { "field" => "ip.src", "operator" => "eq", "value" => "7.7.7.7" } }
        ]
      })

      config = Rack::Attack.configuration
      _(config.blocklists).must_include "block-1"
      _(config.blocklists).must_include "block-2"
    end
  end

  describe "complex conditions from benchmark rules" do
    it "evaluates rules with logical combinators" do
      Rack::Attack.load_ruleset({
        "rules" => [
          { "name" => "sensitive-paths", "type" => "blocklist",
            "condition" => {
              "and" => [
                { "field" => "http.request.uri.path", "operator" => "matches",
                  "value" => "(?i)^/(admin|internal|\\.env)" },
                { "not" => { "field" => "ip.src", "operator" => "in_ip_range",
                             "value" => ["10.0.0.0/8", "127.0.0.0/8"] } }
              ]
            } }
        ]
      })

      config = Rack::Attack.configuration

      # External IP hitting admin path - blocked
      request = make_request("PATH_INFO" => "/admin", "REMOTE_ADDR" => "203.0.113.50")
      _(config.blocklisted?(request)).must_equal true

      # Internal IP hitting admin path - not blocked
      request = make_request("PATH_INFO" => "/admin", "REMOTE_ADDR" => "10.0.0.1")
      _(config.blocklisted?(request)).must_equal false

      # External IP hitting normal path - not blocked
      request = make_request("PATH_INFO" => "/api/users", "REMOTE_ADDR" => "203.0.113.50")
      _(config.blocklisted?(request)).must_equal false
    end
  end

  describe "native engine auto-detection" do
    it "creates rules that work without native engine" do
      # Force no native engine by skipping native compilation
      Rack::Attack.load_ruleset({
        "rules" => [
          { "name" => "safe-health", "type" => "safelist",
            "condition" => { "field" => "http.request.uri.path", "operator" => "eq", "value" => "/healthz" } }
        ]
      })

      config = Rack::Attack.configuration
      request = make_request("PATH_INFO" => "/healthz")
      _(config.safelisted?(request)).must_equal true
    end
  end
end
