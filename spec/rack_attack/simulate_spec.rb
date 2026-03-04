# frozen_string_literal: true

require_relative "test_helper"
require "json"
require "stringio"

describe "Rack::Attack.simulate" do
  before do
    Rack::Attack.clear_configuration
    Rack::Attack.cache.store = ActiveSupport::Cache::MemoryStore.new
  end

  after do
    Rack::Attack.clear_configuration
    Rack::Attack.instance_variable_set(:@cache, nil)
  end

  describe "SimulationResult" do
    it "returns :allow when no rules match" do
      result = Rack::Attack.simulate(ip: "1.2.3.4", path: "/")

      _(result.outcome).must_equal :allow
      _(result.safelisted?).must_equal false
      _(result.blocklisted?).must_equal false
      _(result.throttled?).must_equal false
      _(result.tracked?).must_equal false
      _(result.matched_rules).must_equal []
    end

    it "returns :safelist when a safelist matches" do
      Rack::Attack.safelist("allow-localhost") { |req| req.ip == "127.0.0.1" }

      result = Rack::Attack.simulate(ip: "127.0.0.1")

      _(result.outcome).must_equal :safelist
      _(result.safelisted?).must_equal true
      _(result.safelisted_by).must_equal "allow-localhost"
      _(result.matched_rules).must_include "allow-localhost"
    end

    it "returns :blocklist when a blocklist matches" do
      Rack::Attack.blocklist("block-bad-ip") { |req| req.ip == "6.6.6.6" }

      result = Rack::Attack.simulate(ip: "6.6.6.6")

      _(result.outcome).must_equal :blocklist
      _(result.blocklisted?).must_equal true
      _(result.blocked_by).must_equal "block-bad-ip"
      _(result.matched_rules).must_include "block-bad-ip"
    end

    it "returns :allow for non-matching blocklist" do
      Rack::Attack.blocklist("block-bad-ip") { |req| req.ip == "6.6.6.6" }

      result = Rack::Attack.simulate(ip: "1.2.3.4")

      _(result.outcome).must_equal :allow
      _(result.blocklisted?).must_equal false
    end

    it "returns throttle matches with metadata" do
      Rack::Attack.throttle("limit-login", limit: 5, period: 60) do |req|
        req.ip if req.path == "/login"
      end

      result = Rack::Attack.simulate(ip: "1.2.3.4", path: "/login", method: "POST")

      _(result.throttle_matches.length).must_equal 1
      match = result.throttle_matches.first
      _(match[:name]).must_equal "limit-login"
      _(match[:limit]).must_equal 5
      _(match[:period]).must_equal 60
      _(match[:discriminator]).must_equal "1.2.3.4"
    end

    it "does not match throttle when discriminator is nil" do
      Rack::Attack.throttle("limit-login", limit: 5, period: 60) do |req|
        req.ip if req.path == "/login"
      end

      result = Rack::Attack.simulate(ip: "1.2.3.4", path: "/other")

      _(result.throttle_matches).must_be_empty
    end

    it "returns track matches" do
      Rack::Attack.track("track-api") { |req| req.path.start_with?("/api") }

      result = Rack::Attack.simulate(path: "/api/v1/users")

      _(result.tracked?).must_equal true
      _(result.track_matches).must_include "track-api"
    end

    it "collects all matched rules" do
      Rack::Attack.blocklist("block-ip") { |req| req.ip == "6.6.6.6" }
      Rack::Attack.track("track-all") { |_req| true }

      result = Rack::Attack.simulate(ip: "6.6.6.6")

      _(result.matched_rules).must_include "block-ip"
      _(result.matched_rules).must_include "track-all"
    end
  end

  describe "with JSON rules" do
    it "simulates blocklist from JSON ruleset" do
      Rack::Attack.load_ruleset({
        "rules" => [
          {
            "name" => "block-bad-ips",
            "type" => "blocklist",
            "condition" => { "field" => "ip.src", "operator" => "in", "value" => ["6.6.6.6", "9.9.9.9"] }
          }
        ]
      })

      result = Rack::Attack.simulate(ip: "6.6.6.6")
      _(result.blocklisted?).must_equal true
      _(result.blocked_by).must_equal "block-bad-ips"

      result = Rack::Attack.simulate(ip: "1.2.3.4")
      _(result.blocklisted?).must_equal false
    end

    it "simulates safelist from JSON ruleset" do
      Rack::Attack.load_ruleset({
        "rules" => [
          {
            "name" => "allow-health",
            "type" => "safelist",
            "condition" => { "field" => "http.request.uri.path", "operator" => "eq", "value" => "/healthz" }
          }
        ]
      })

      result = Rack::Attack.simulate(path: "/healthz")
      _(result.safelisted?).must_equal true
      _(result.safelisted_by).must_equal "allow-health"
    end

    it "simulates throttle from JSON ruleset" do
      Rack::Attack.load_ruleset({
        "rules" => [
          {
            "name" => "rate-limit",
            "type" => "throttle",
            "limit" => 10,
            "period" => 60,
            "key" => ["ip.src"],
            "condition" => { "field" => "http.request.uri.path", "operator" => "starts_with", "value" => "/api" }
          }
        ]
      })

      result = Rack::Attack.simulate(ip: "1.2.3.4", path: "/api/users")
      _(result.throttle_matches.length).must_equal 1
      _(result.throttle_matches.first[:name]).must_equal "rate-limit"
      _(result.throttle_matches.first[:limit]).must_equal 10
    end

    it "simulates track from JSON ruleset" do
      Rack::Attack.load_ruleset({
        "rules" => [
          {
            "name" => "track-admin",
            "type" => "track",
            "condition" => { "field" => "http.request.uri.path", "operator" => "starts_with", "value" => "/admin" }
          }
        ]
      })

      result = Rack::Attack.simulate(path: "/admin/dashboard")
      _(result.tracked?).must_equal true
      _(result.track_matches).must_include "track-admin"
    end
  end

  describe "request building" do
    it "builds request with custom headers" do
      Rack::Attack.blocklist("block-bot") do |req|
        req.user_agent == "BadBot"
      end

      result = Rack::Attack.simulate(user_agent: "BadBot")
      _(result.blocklisted?).must_equal true
    end

    it "builds request with custom method" do
      Rack::Attack.blocklist("block-delete") do |req|
        req.request_method == "DELETE"
      end

      result = Rack::Attack.simulate(method: "DELETE")
      _(result.blocklisted?).must_equal true
    end

    it "builds request with headers hash" do
      Rack::Attack.blocklist("block-header") do |req|
        req.env["HTTP_X_CUSTOM"] == "blocked"
      end

      result = Rack::Attack.simulate(headers: { "X-Custom" => "blocked" })
      _(result.blocklisted?).must_equal true
    end

    it "builds request with cookies" do
      Rack::Attack.load_ruleset({
        "rules" => [
          {
            "name" => "track-session",
            "type" => "track",
            "condition" => {
              "field" => 'http.request.cookies["session"]',
              "operator" => "exists"
            }
          }
        ]
      })

      result = Rack::Attack.simulate(cookies: { "session" => "abc123" })
      _(result.tracked?).must_equal true
    end

    it "defaults to sensible values" do
      Rack::Attack.safelist("allow-localhost") { |req| req.ip == "127.0.0.1" }

      # Default IP is 127.0.0.1
      result = Rack::Attack.simulate
      _(result.safelisted?).must_equal true
    end
  end

  describe "simulate_throttle" do
    it "reports throttle when count exceeds limit" do
      Rack::Attack.throttle("login-limit", limit: 5, period: 60) do |req|
        req.ip if req.path == "/login"
      end

      result = Rack::Attack.simulate_throttle(count: 6, ip: "1.2.3.4", path: "/login")
      _(result.throttled?).must_equal true

      result = Rack::Attack.simulate_throttle(count: 5, ip: "1.2.3.4", path: "/login")
      _(result.throttled?).must_equal false
    end

    it "returns empty result when no throttle matches" do
      Rack::Attack.throttle("login-limit", limit: 5, period: 60) do |req|
        req.ip if req.path == "/login"
      end

      result = Rack::Attack.simulate_throttle(count: 100, ip: "1.2.3.4", path: "/other")
      _(result.throttled?).must_equal false
    end
  end

  describe "does not produce side effects" do
    it "does not mutate the cache" do
      Rack::Attack.throttle("rate-limit", limit: 5, period: 60) { |req| req.ip }

      Rack::Attack.simulate(ip: "1.2.3.4")
      Rack::Attack.simulate(ip: "1.2.3.4")
      Rack::Attack.simulate(ip: "1.2.3.4")

      # The cache should not have been incremented
      # Verify by making a real request through the middleware
      get "/", {}, "REMOTE_ADDR" => "1.2.3.4"
      _(last_response.status).must_equal 200
    end

    it "does not trigger instrumentation" do
      events = []
      subscriber = lambda { |*args| events << args }

      if defined?(ActiveSupport::Notifications)
        ActiveSupport::Notifications.subscribe("blocklist.rack_attack", &subscriber)
      end

      Rack::Attack.blocklist("block-test") { |req| req.ip == "6.6.6.6" }
      Rack::Attack.simulate(ip: "6.6.6.6")

      _(events).must_be_empty
    ensure
      if defined?(ActiveSupport::Notifications)
        ActiveSupport::Notifications.unsubscribe(subscriber) if subscriber
      end
    end
  end
end
