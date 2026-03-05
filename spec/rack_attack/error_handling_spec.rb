# frozen_string_literal: true

require_relative "test_helper"
require "json"
require "stringio"
require "base64"

describe "Error handling" do
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
  # User blocks that raise exceptions
  # ===========================================================================

  describe "user blocks that raise exceptions" do
    it "blocklist block that raises does not crash the middleware" do
      Rack::Attack.blocklist("raising-block") { |_req| raise RuntimeError, "user code error" }

      request = make_request("REMOTE_ADDR" => "1.2.3.4")
      # Should fail open (not matched), not crash
      result = Rack::Attack.configuration.blocklisted?(request)
      _(result).must_equal false
    end

    it "safelist block that raises does not crash the middleware" do
      Rack::Attack.safelist("raising-safe") { |_req| raise StandardError, "oops" }

      request = make_request("PATH_INFO" => "/healthz")
      result = Rack::Attack.configuration.safelisted?(request)
      _(result).must_equal false
    end

    it "track block that raises does not crash the middleware" do
      Rack::Attack.track("raising-track") { |_req| raise "track error" }

      request = make_request
      # tracked? iterates all tracks; a raising block should not crash
      Rack::Attack.configuration.tracked?(request)
      # If we get here without exception, the test passes
      assert_operator true, :==, true
    end

    it "throttle block that raises does not crash the middleware" do
      Rack::Attack.throttle("raising-throttle", limit: 5, period: 60) do |_req|
        raise "throttle error"
      end

      request = make_request
      result = Rack::Attack.configuration.throttled?(request)
      _(result).must_equal false
    end

    it "multiple rules where one raises still evaluates others" do
      Rack::Attack.blocklist("raising-first") { |_req| raise "first rule error" }
      Rack::Attack.blocklist("working-second") { |req| req.ip == "6.6.6.6" }

      request = make_request("REMOTE_ADDR" => "6.6.6.6")
      result = Rack::Attack.configuration.blocklisted?(request)
      # The second rule should still match despite the first raising
      _(result).must_equal true
    end
  end

  # ===========================================================================
  # JWT evaluation with bad/missing config
  # ===========================================================================

  describe "JWT evaluation with bad config" do
    it "jwt field access with nil jwt_config returns false" do
      request = make_request("HTTP_AUTHORIZATION" => "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMSJ9.fakesig")
      cond = { "field" => "jwt.valid", "operator" => "eq", "value" => "true" }
      result = Rack::Attack::ConditionEvaluator.match?(cond, request, jwt_config: nil)
      _(result).must_equal false
    end

    it "jwt field access with empty jwt_config array returns false for jwt.valid" do
      request = make_request("HTTP_AUTHORIZATION" => "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMSJ9.fakesig")
      cond = { "field" => "jwt.valid", "operator" => "eq", "value" => "true" }
      result = Rack::Attack::ConditionEvaluator.match?(cond, request, jwt_config: [])
      _(result).must_equal false
    end

    it "jwt field access with invalid key entry does not crash" do
      # Config with a key that will fail to verify — should not raise
      bad_config = [{ "algorithm" => "RS256", "key" => "not-a-real-pem-key" }]
      request = make_request("HTTP_AUTHORIZATION" => "Bearer eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyMSJ9.fakesig")
      cond = { "field" => "jwt.valid", "operator" => "eq", "value" => "true" }
      result = Rack::Attack::ConditionEvaluator.match?(cond, request, jwt_config: bad_config)
      _(result).must_equal false
    end

    it "unverified jwt payload access still works without jwt_config" do
      # Base64-encoded header and payload
      header = Base64.urlsafe_encode64('{"alg":"HS256"}', padding: false)
      payload = Base64.urlsafe_encode64('{"sub":"user1"}', padding: false)
      token = "#{header}.#{payload}.fakesig"

      request = make_request("HTTP_AUTHORIZATION" => "Bearer #{token}")
      cond = { "field" => 'jwt.payload["sub"]', "operator" => "eq", "value" => "user1" }
      result = Rack::Attack::ConditionEvaluator.match?(cond, request, jwt_config: nil)
      # Unverified decode should work even without jwt_config
      _(result).must_equal true
    end

    it "jwt.valid returns false when no Authorization header at all" do
      request = make_request
      cond = { "field" => "jwt.valid", "operator" => "eq", "value" => "true" }
      result = Rack::Attack::ConditionEvaluator.match?(cond, request, jwt_config: [{ "algorithm" => "HS256", "key" => "secret" }])
      _(result).must_equal false
    end

    it "jwt.payload returns false for completely garbled token" do
      request = make_request("HTTP_AUTHORIZATION" => "Bearer not.valid.base64!!!")
      cond = { "field" => 'jwt.payload["sub"]', "operator" => "exists" }
      result = Rack::Attack::ConditionEvaluator.match?(cond, request)
      _(result).must_equal false
    end
  end

  # ===========================================================================
  # Native evaluation error handling
  # ===========================================================================

  describe "native evaluation error handling" do
    it "warns and returns nil when native ruleset raises during evaluation" do
      Rack::Attack.load_ruleset({
        "rules" => [{
          "name" => "test-rule",
          "type" => "blocklist",
          "condition" => { "field" => "ip.src", "operator" => "eq", "value" => "6.6.6.6" }
        }]
      })

      config = Rack::Attack.configuration

      # Replace native_ruleset with an object that raises
      mock_ruleset = Object.new
      def mock_ruleset.evaluate(_data)
        raise StandardError, "native engine crash"
      end
      config.instance_variable_set(:@native_ruleset, mock_ruleset)

      request = make_request("REMOTE_ADDR" => "6.6.6.6")

      # Should not crash — falls back to Ruby evaluation
      result = config.blocklisted?(request)
      # Ruby fallback should still work
      _(result).must_equal true
    end
  end
end
