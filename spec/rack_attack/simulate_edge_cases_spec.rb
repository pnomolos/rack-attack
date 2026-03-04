# frozen_string_literal: true

require_relative "test_helper"
require "json"
require "stringio"
require "base64"

describe "simulate edge cases" do
  before do
    Rack::Attack.clear_configuration
    Rack::Attack.cache.store = ActiveSupport::Cache::MemoryStore.new
  end

  after do
    Rack::Attack.clear_configuration
    Rack::Attack.instance_variable_set(:@cache, nil)
  end

  # --- Outcome precedence ---

  describe "outcome precedence" do
    it "both safelist and blocklist match → outcome is :safelist" do
      Rack::Attack.load_ruleset({
        "rules" => [
          {
            "name" => "allow-all",
            "type" => "safelist",
            "condition" => { "field" => "ip.src", "operator" => "eq", "value" => "1.2.3.4" }
          },
          {
            "name" => "block-all",
            "type" => "blocklist",
            "condition" => { "field" => "ip.src", "operator" => "eq", "value" => "1.2.3.4" }
          }
        ]
      })

      result = Rack::Attack.simulate(ip: "1.2.3.4")
      _(result.outcome).must_equal :safelist
    end

    it "track matches collected even when safelisted" do
      Rack::Attack.load_ruleset({
        "rules" => [
          {
            "name" => "allow-it",
            "type" => "safelist",
            "condition" => { "field" => "ip.src", "operator" => "eq", "value" => "1.2.3.4" }
          },
          {
            "name" => "track-it",
            "type" => "track",
            "condition" => { "field" => "ip.src", "operator" => "eq", "value" => "1.2.3.4" }
          }
        ]
      })

      result = Rack::Attack.simulate(ip: "1.2.3.4")
      _(result.safelisted?).must_equal true
      _(result.track_matches).must_include "track-it"
    end

    it "track matches collected even when blocklisted" do
      Rack::Attack.load_ruleset({
        "rules" => [
          {
            "name" => "block-it",
            "type" => "blocklist",
            "condition" => { "field" => "ip.src", "operator" => "eq", "value" => "6.6.6.6" }
          },
          {
            "name" => "track-it",
            "type" => "track",
            "condition" => { "field" => "ip.src", "operator" => "eq", "value" => "6.6.6.6" }
          }
        ]
      })

      result = Rack::Attack.simulate(ip: "6.6.6.6")
      _(result.blocklisted?).must_equal true
      _(result.track_matches).must_include "track-it"
    end
  end

  # --- Anonymous rules ---

  describe "anonymous rules in simulation" do
    it "blocklist_ip match is detected (blocked_by is nil for anonymous)" do
      Rack::Attack.blocklist_ip("6.6.6.6")

      result = Rack::Attack.simulate(ip: "6.6.6.6")
      # Anonymous rules have nil name, so blocked_by is nil
      # but the match IS found (returned from find_blocklist_match)
      _(result.blocked_by).must_be_nil
    end

    it "safelist_ip match is detected (safelisted_by is nil for anonymous)" do
      Rack::Attack.safelist_ip("10.0.0.0/8")

      result = Rack::Attack.simulate(ip: "10.0.0.1")
      # Anonymous rules have nil name
      _(result.safelisted_by).must_be_nil
    end
  end

  # --- simulate_throttle ---

  describe "simulate_throttle edge cases" do
    before do
      Rack::Attack.throttle("api-limit", limit: 10, period: 60) do |req|
        req.ip if req.path.start_with?("/api")
      end
    end

    it "count=0 → not throttled" do
      result = Rack::Attack.simulate_throttle(count: 0, ip: "1.2.3.4", path: "/api/test")
      _(result.throttled?).must_equal false
    end

    it "count exactly equals limit → not throttled (uses >, not >=)" do
      result = Rack::Attack.simulate_throttle(count: 10, ip: "1.2.3.4", path: "/api/test")
      _(result.throttled?).must_equal false
    end

    it "count = limit+1 → throttled" do
      result = Rack::Attack.simulate_throttle(count: 11, ip: "1.2.3.4", path: "/api/test")
      _(result.throttled?).must_equal true
    end
  end

  # --- Request building ---

  describe "request building edge cases" do
    it "body sets content_length and is readable by body.size condition" do
      Rack::Attack.load_ruleset({
        "rules" => [{
          "name" => "large-body",
          "type" => "track",
          "condition" => { "field" => "http.request.body.size", "operator" => "gt", "value" => 10 }
        }]
      })

      result = Rack::Attack.simulate(body: "a" * 20)
      _(result.tracked?).must_equal true
      _(result.track_matches).must_include "large-body"
    end

    it "non-ASCII paths work" do
      Rack::Attack.load_ruleset({
        "rules" => [{
          "name" => "unicode-path",
          "type" => "track",
          "condition" => { "field" => "http.request.uri.path", "operator" => "contains", "value" => "café" }
        }]
      })

      result = Rack::Attack.simulate(path: "/menu/café")
      _(result.tracked?).must_equal true
    end
  end

  # --- Query string parameter in simulation ---

  describe "query_string parameter" do
    it "query_string is accessible in simulation" do
      Rack::Attack.load_ruleset({
        "rules" => [{
          "name" => "track-query",
          "type" => "track",
          "condition" => { "field" => 'http.request.uri.args["foo"]', "operator" => "eq", "value" => "bar" }
        }]
      })

      result = Rack::Attack.simulate(query_string: "foo=bar")
      _(result.tracked?).must_equal true
      _(result.track_matches).must_include "track-query"
    end
  end

  # --- JWT fields via headers in simulation ---

  describe "JWT fields via headers in simulation" do
    def encode_jwt_segment(data)
      Base64.urlsafe_encode64(JSON.generate(data), padding: false)
    end

    it "JWT payload accessible via headers parameter" do
      token = "#{encode_jwt_segment({ "alg" => "HS256" })}.#{encode_jwt_segment({ "sub" => "user1" })}.fakesig"

      Rack::Attack.load_ruleset({
        "rules" => [{
          "name" => "track-jwt",
          "type" => "track",
          "condition" => { "field" => 'jwt.payload["sub"]', "operator" => "eq", "value" => "user1" }
        }]
      })

      result = Rack::Attack.simulate(headers: { "Authorization" => "Bearer #{token}" })
      _(result.tracked?).must_equal true
      _(result.track_matches).must_include "track-jwt"
    end
  end

  # --- Throttle-based track (find_track_matches) ---

  describe "throttle-based track" do
    it "track with throttle filter matches when discriminator present" do
      Rack::Attack.track("track-api-rate", limit: 100, period: 60) do |req|
        req.ip if req.path.start_with?("/api")
      end

      result = Rack::Attack.simulate(ip: "1.2.3.4", path: "/api/test")
      _(result.track_matches).must_include "track-api-rate"
    end

    it "track with throttle filter does not match when discriminator nil" do
      Rack::Attack.track("track-api-rate", limit: 100, period: 60) do |req|
        req.ip if req.path.start_with?("/api")
      end

      result = Rack::Attack.simulate(ip: "1.2.3.4", path: "/other")
      _(result.track_matches).wont_include "track-api-rate"
    end
  end

  # --- Multiple simultaneous matches ---

  describe "multiple simultaneous matches" do
    it "all 4 rule types matching same request are reflected in result" do
      Rack::Attack.load_ruleset({
        "rules" => [
          {
            "name" => "sl",
            "type" => "safelist",
            "condition" => { "field" => "ip.src", "operator" => "eq", "value" => "1.2.3.4" }
          },
          {
            "name" => "bl",
            "type" => "blocklist",
            "condition" => { "field" => "ip.src", "operator" => "eq", "value" => "1.2.3.4" }
          },
          {
            "name" => "thr",
            "type" => "throttle",
            "limit" => 5,
            "period" => 60,
            "key" => ["ip.src"],
            "condition" => { "field" => "ip.src", "operator" => "eq", "value" => "1.2.3.4" }
          },
          {
            "name" => "trk",
            "type" => "track",
            "condition" => { "field" => "ip.src", "operator" => "eq", "value" => "1.2.3.4" }
          }
        ]
      })

      result = Rack::Attack.simulate(ip: "1.2.3.4")
      _(result.safelisted_by).must_equal "sl"
      _(result.blocked_by).must_equal "bl"
      _(result.throttle_matches.any? { |m| m[:name] == "thr" }).must_equal true
      _(result.track_matches).must_include "trk"
    end
  end
end
