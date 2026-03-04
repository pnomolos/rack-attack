# frozen_string_literal: true

require_relative "test_helper"
require "json"
require "stringio"

describe "Native bridge and fallback behavior" do
  before do
    Rack::Attack.clear_configuration
    Rack::Attack.cache.store = ActiveSupport::Cache::MemoryStore.new
  end

  after do
    Rack::Attack.clear_configuration
    Rack::Attack.instance_variable_set(:@cache, nil)
  end

  # --- NativeBridge.available? ---

  describe "NativeBridge.available?" do
    it "returns a boolean (not nil)" do
      result = Rack::Attack::NativeBridge.available?
      _([true, false]).must_include result
    end
  end

  # --- Fallback when native unavailable ---

  describe "fallback when native unavailable" do
    it "Ruby evaluation works when NativeBridge.available? stubbed to false" do
      # Stub native to be unavailable by setting @native_ruleset to nil
      Rack::Attack.load_ruleset({
        "rules" => [{
          "name" => "block-ip",
          "type" => "blocklist",
          "condition" => { "field" => "ip.src", "operator" => "eq", "value" => "6.6.6.6" }
        }]
      })

      # Force native_ruleset to nil to simulate native being unavailable
      Rack::Attack.configuration.instance_variable_set(:@native_ruleset, nil)

      # Ruby fallback should still work via the registered Ruby blocks
      get "/", {}, "REMOTE_ADDR" => "6.6.6.6"
      _(last_response.status).must_equal 403
    end

    it "@native_ruleset is nil when native unavailable" do
      # Save and stub available?
      original = Rack::Attack::NativeBridge.instance_variable_get(:@available)
      Rack::Attack::NativeBridge.instance_variable_set(:@available, false)

      Rack::Attack.load_ruleset({ "rules" => [] })
      config = Rack::Attack.configuration
      _(config.instance_variable_get(:@native_ruleset)).must_be_nil

      Rack::Attack::NativeBridge.instance_variable_set(:@available, original)
    end
  end

  # --- stringify_native_result ---

  describe "stringify_native_result" do
    def stringify(result)
      Rack::Attack.configuration.send(:stringify_native_result, result)
    end

    it "converts symbol keys to string keys" do
      result = stringify({ foo: "bar", baz: 1 })
      _(result).must_equal({ "foo" => "bar", "baz" => 1 })
    end

    it "handles nested hashes and arrays" do
      result = stringify({ outer: { inner: "val" }, list: [{ a: 1 }, "plain"] })
      _(result).must_equal({ "outer" => { "inner" => "val" }, "list" => [{ "a" => 1 }, "plain"] })
    end

    it "returns non-hash input unchanged" do
      _(stringify("hello")).must_equal "hello"
      _(stringify(42)).must_equal 42
      _(stringify(nil)).must_be_nil
    end

    it "handles empty hash" do
      _(stringify({})).must_equal({})
    end
  end

  # --- evaluate_native error handling ---

  describe "evaluate_native error handling" do
    it "evaluate_native warns and returns nil when native_ruleset raises" do
      Rack::Attack.load_ruleset({
        "rules" => [{
          "name" => "block-ip",
          "type" => "blocklist",
          "condition" => { "field" => "ip.src", "operator" => "eq", "value" => "6.6.6.6" }
        }]
      })

      config = Rack::Attack.configuration
      # Replace native_ruleset with an object that raises on evaluate
      mock_ruleset = Object.new
      def mock_ruleset.evaluate(_data)
        raise StandardError, "native crash"
      end
      config.instance_variable_set(:@native_ruleset, mock_ruleset)

      env = {
        "REQUEST_METHOD" => "GET",
        "PATH_INFO" => "/",
        "QUERY_STRING" => "",
        "REMOTE_ADDR" => "6.6.6.6",
        "HTTP_HOST" => "example.com",
        "rack.input" => StringIO.new(""),
        "SERVER_NAME" => "example.com",
        "SERVER_PORT" => "80"
      }
      request = Rack::Attack::Request.new(env)

      # Should not crash — returns nil and falls back to Ruby
      result = config.send(:evaluate_native, request)
      _(result).must_be_nil
    end
  end

  # --- request_to_native ---

  describe "request_to_native" do
    def build_env(overrides = {})
      {
        "REQUEST_METHOD" => "GET",
        "PATH_INFO" => "/test",
        "QUERY_STRING" => "q=1",
        "REMOTE_ADDR" => "192.168.1.1",
        "HTTP_HOST" => "example.com",
        "HTTP_USER_AGENT" => "TestBot/1.0",
        "rack.input" => StringIO.new(""),
        "SERVER_NAME" => "example.com",
        "SERVER_PORT" => "80"
      }.merge(overrides)
    end

    it "produces correct hash structure from a Rack request" do
      request = Rack::Attack::Request.new(build_env)
      native = Rack::Attack::NativeBridge.request_to_native(request)

      _(native["path"]).must_equal "/test"
      _(native["method"]).must_equal "GET"
      _(native["ip"]).must_equal "192.168.1.1"
      _(native["user_agent"]).must_equal "TestBot/1.0"
      _(native["host"]).must_equal "example.com"
      _(native["query_string"]).must_equal "q=1"
      _(native).must_be_kind_of Hash
    end

    it "handles request with no body (nil body)" do
      env = build_env("rack.input" => StringIO.new(""))
      request = Rack::Attack::Request.new(env)
      native = Rack::Attack::NativeBridge.request_to_native(request)

      # body should be empty string from reading empty StringIO
      _(native["body"]).must_equal ""
    end

    it "handles request with cookies" do
      env = build_env("HTTP_COOKIE" => "session=abc; token=xyz")
      request = Rack::Attack::Request.new(env)
      native = Rack::Attack::NativeBridge.request_to_native(request)

      _(native["cookies"]).must_be_kind_of Hash
      _(native["cookies"]["session"]).must_equal "abc"
      _(native["cookies"]["token"]).must_equal "xyz"
    end

    it "excludes HTTP_HOST, HTTP_USER_AGENT, HTTP_AUTHORIZATION from headers sub-hash" do
      env = build_env(
        "HTTP_AUTHORIZATION" => "Bearer token123",
        "HTTP_X_CUSTOM" => "custom-value"
      )
      request = Rack::Attack::Request.new(env)
      native = Rack::Attack::NativeBridge.request_to_native(request)

      headers = native["headers"]
      _(headers).wont_include "host"
      _(headers).wont_include "user-agent"
      _(headers).wont_include "authorization"
      _(headers["x-custom"]).must_equal "custom-value"
    end
  end
end
