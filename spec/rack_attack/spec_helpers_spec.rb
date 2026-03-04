# frozen_string_literal: true

require_relative "test_helper"
require "rack/attack/spec_helpers/minitest"

describe "Rack::Attack::MinitestHelpers" do
  include Rack::Attack::MinitestHelpers

  before do
    Rack::Attack.clear_configuration
    Rack::Attack.cache.store = ActiveSupport::Cache::MemoryStore.new
  end

  after do
    Rack::Attack.clear_configuration
    Rack::Attack.instance_variable_set(:@cache, nil)
  end

  describe "assert_safelisted" do
    it "passes when request is safelisted" do
      Rack::Attack.safelist("allow-local") { |req| req.ip == "127.0.0.1" }

      assert_safelisted(ip: "127.0.0.1")
    end
  end

  describe "assert_safelisted_by" do
    it "passes when request is safelisted by the named rule" do
      Rack::Attack.safelist("allow-local") { |req| req.ip == "127.0.0.1" }

      assert_safelisted_by("allow-local", ip: "127.0.0.1")
    end
  end

  describe "assert_blocklisted" do
    it "passes when request is blocklisted" do
      Rack::Attack.blocklist("block-ip") { |req| req.ip == "6.6.6.6" }

      assert_blocklisted(ip: "6.6.6.6")
    end
  end

  describe "assert_blocklisted_by" do
    it "passes when request is blocklisted by the named rule" do
      Rack::Attack.blocklist("block-ip") { |req| req.ip == "6.6.6.6" }

      assert_blocklisted_by("block-ip", ip: "6.6.6.6")
    end
  end

  describe "assert_throttled_on" do
    it "passes when request matches the named throttle" do
      Rack::Attack.throttle("rate-limit", limit: 10, period: 60) { |req| req.ip }

      assert_throttled_on("rate-limit", ip: "1.2.3.4")
    end
  end

  describe "assert_tracked_by" do
    it "passes when request is tracked by the named rule" do
      Rack::Attack.track("track-api") { |req| req.path.start_with?("/api") }

      assert_tracked_by("track-api", path: "/api/v1")
    end
  end

  describe "assert_allowed" do
    it "passes when request is allowed" do
      Rack::Attack.blocklist("block-ip") { |req| req.ip == "6.6.6.6" }

      assert_allowed(ip: "1.2.3.4")
    end
  end

  describe "assert_throttled_after" do
    it "passes when the throttle limit matches expected count" do
      Rack::Attack.throttle("login-limit", limit: 5, period: 60) do |req|
        req.ip if req.path == "/login"
      end

      assert_throttled_after(5, path: "/login", ip: "1.2.3.4")
    end
  end

  describe "with JSON rules" do
    it "works with loaded JSON rulesets" do
      Rack::Attack.load_ruleset({
        "rules" => [
          {
            "name" => "block-bad-ips",
            "type" => "blocklist",
            "condition" => {
              "field" => "ip.src",
              "operator" => "in",
              "value" => ["6.6.6.6", "9.9.9.9"]
            }
          },
          {
            "name" => "allow-health",
            "type" => "safelist",
            "condition" => {
              "field" => "http.request.uri.path",
              "operator" => "eq",
              "value" => "/healthz"
            }
          },
          {
            "name" => "api-rate-limit",
            "type" => "throttle",
            "limit" => 100,
            "period" => 60,
            "key" => ["ip.src"],
            "condition" => {
              "field" => "http.request.uri.path",
              "operator" => "starts_with",
              "value" => "/api"
            }
          },
          {
            "name" => "track-admin",
            "type" => "track",
            "condition" => {
              "field" => "http.request.uri.path",
              "operator" => "starts_with",
              "value" => "/admin"
            }
          }
        ]
      })

      assert_blocklisted_by("block-bad-ips", ip: "6.6.6.6")
      assert_safelisted_by("allow-health", path: "/healthz")
      assert_throttled_on("api-rate-limit", path: "/api/users")
      assert_tracked_by("track-admin", path: "/admin/dashboard")
      assert_allowed(ip: "1.2.3.4", path: "/home")
    end
  end
end
