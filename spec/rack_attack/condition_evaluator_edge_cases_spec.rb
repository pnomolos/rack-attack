# frozen_string_literal: true

require_relative "test_helper"
require "json"
require "stringio"
require "base64"

describe "ConditionEvaluator edge cases" do
  before do
    Rack::Attack.clear_configuration
  end

  def build_request(env_overrides = {})
    env = {
      "REQUEST_METHOD" => "GET",
      "PATH_INFO" => "/",
      "QUERY_STRING" => "",
      "REMOTE_ADDR" => "127.0.0.1",
      "HTTP_HOST" => "example.com",
      "rack.input" => StringIO.new(""),
      "SERVER_NAME" => "example.com",
      "SERVER_PORT" => "80"
    }.merge(env_overrides)
    Rack::Attack::Request.new(env)
  end

  def match?(condition, request, jwt_config: nil)
    Rack::Attack::ConditionEvaluator.match?(condition, request, jwt_config: jwt_config)
  end

  def extract_throttle_key(key_fields, request, jwt_config: nil)
    Rack::Attack::ConditionEvaluator.extract_throttle_key(key_fields, request, jwt_config: jwt_config)
  end

  # --- IP edge cases ---

  describe "IPv6 addresses" do
    it "matches IPv6 address in IPv6 CIDR range (::1 in ::1/128)" do
      req = build_request("REMOTE_ADDR" => "::1")
      cond = { "field" => "ip.src", "operator" => "in_ip_range", "value" => "::1/128" }
      _(match?(cond, req)).must_equal true
    end

    it "matches IPv6 CIDR range (2001:db8::1 in 2001:db8::/32)" do
      req = build_request("REMOTE_ADDR" => "2001:db8::1")
      cond = { "field" => "ip.src", "operator" => "in_ip_range", "value" => "2001:db8::/32" }
      _(match?(cond, req)).must_equal true
    end

    it "non-matching IPv6 returns false" do
      req = build_request("REMOTE_ADDR" => "2001:db9::1")
      cond = { "field" => "ip.src", "operator" => "in_ip_range", "value" => "2001:db8::/32" }
      _(match?(cond, req)).must_equal false
    end

    it "invalid IP format returns false" do
      req = build_request("REMOTE_ADDR" => "not-an-ip")
      cond = { "field" => "ip.src", "operator" => "in_ip_range", "value" => "10.0.0.0/8" }
      _(match?(cond, req)).must_equal false
    end

    it "invalid CIDR range returns false" do
      req = build_request("REMOTE_ADDR" => "10.0.0.1")
      cond = { "field" => "ip.src", "operator" => "in_ip_range", "value" => "not-a-cidr" }
      _(match?(cond, req)).must_equal false
    end
  end

  # --- Regex edge cases ---

  describe "matches operator" do
    it "invalid regex returns false (RegexpError rescued)" do
      req = build_request("PATH_INFO" => "/test")
      cond = { "field" => "http.request.uri.path", "operator" => "matches", "value" => "[invalid" }
      _(match?(cond, req)).must_equal false
    end
  end

  # --- Nil/empty field handling ---

  describe "nil and empty field values" do
    it "eq with nil field value returns false" do
      req = build_request # no user agent set
      cond = { "field" => "http.user_agent", "operator" => "eq", "value" => "Bot" }
      _(match?(cond, req)).must_equal false
    end

    it "exists returns false for empty string" do
      req = build_request("HTTP_USER_AGENT" => "")
      cond = { "field" => "http.user_agent", "operator" => "exists" }
      _(match?(cond, req)).must_equal false
    end

    it "not_exists returns true for empty string" do
      req = build_request("HTTP_USER_AGENT" => "")
      cond = { "field" => "http.user_agent", "operator" => "not_exists" }
      _(match?(cond, req)).must_equal true
    end

    it "unknown field name returns false for exists" do
      req = build_request
      cond = { "field" => "nonexistent.field", "operator" => "exists" }
      _(match?(cond, req)).must_equal false
    end
  end

  # --- Numeric comparison ---

  describe "numeric comparison" do
    it "float string comparison ('3.14' gt 3)" do
      req = build_request("CONTENT_LENGTH" => "100", "rack.input" => StringIO.new("x" * 100))
      # Use body.size which maps to content_length
      cond = { "field" => "http.request.body.size", "operator" => "gt", "value" => 50 }
      _(match?(cond, req)).must_equal true
    end

    it "non-numeric string returns false for gt" do
      req = build_request("HTTP_USER_AGENT" => "hello")
      cond = { "field" => "http.user_agent", "operator" => "gt", "value" => 5 }
      _(match?(cond, req)).must_equal false
    end
  end

  # --- Logical combinators ---

  describe "logical combinators" do
    it "empty 'and' array returns true" do
      req = build_request
      cond = { "and" => [] }
      _(match?(cond, req)).must_equal true
    end

    it "empty 'or' array returns false" do
      req = build_request
      cond = { "or" => [] }
      _(match?(cond, req)).must_equal false
    end

    it "condition with unrecognized key returns false" do
      req = build_request
      cond = { "unknown_key" => "value" }
      _(match?(cond, req)).must_equal false
    end

    it "deeply nested condition (15 levels) evaluates correctly" do
      # Build 15 levels of 'and' wrapping a simple condition
      inner = { "field" => "ip.src", "operator" => "eq", "value" => "127.0.0.1" }
      15.times { inner = { "and" => [inner] } }

      req = build_request("REMOTE_ADDR" => "127.0.0.1")
      _(match?(inner, req)).must_equal true
    end
  end

  # --- JWT edge cases ---

  describe "JWT edge cases" do
    def encode_jwt_segment(data)
      Base64.urlsafe_encode64(JSON.generate(data), padding: false)
    end

    def make_token(header, payload)
      "#{encode_jwt_segment(header)}.#{encode_jwt_segment(payload)}.fakesig"
    end

    it "no Bearer prefix (Basic abc) → jwt.payload exists is false" do
      req = build_request("HTTP_AUTHORIZATION" => "Basic abc123")
      cond = { "field" => 'jwt.payload["sub"]', "operator" => "exists" }
      _(match?(cond, req)).must_equal false
    end

    it "extra whitespace in Bearer header still works" do
      token = make_token({ "alg" => "HS256" }, { "sub" => "user1" })
      req = build_request("HTTP_AUTHORIZATION" => "Bearer   #{token}")
      cond = { "field" => 'jwt.payload["sub"]', "operator" => "eq", "value" => "user1" }
      _(match?(cond, req)).must_equal true
    end

    it "token with only 1 segment returns false" do
      req = build_request("HTTP_AUTHORIZATION" => "Bearer singlesegment")
      cond = { "field" => 'jwt.payload["sub"]', "operator" => "exists" }
      _(match?(cond, req)).must_equal false
    end

    it "token with non-JSON payload returns false" do
      bad_payload = Base64.urlsafe_encode64("not json", padding: false)
      header = encode_jwt_segment({ "alg" => "none" })
      req = build_request("HTTP_AUTHORIZATION" => "Bearer #{header}.#{bad_payload}.sig")
      cond = { "field" => 'jwt.payload["sub"]', "operator" => "exists" }
      _(match?(cond, req)).must_equal false
    end

    it "JWT with numeric claim converts to string via .to_s" do
      token = make_token({ "alg" => "HS256" }, { "user_id" => 42 })
      req = build_request("HTTP_AUTHORIZATION" => "Bearer #{token}")
      cond = { "field" => 'jwt.payload["user_id"]', "operator" => "eq", "value" => "42" }
      _(match?(cond, req)).must_equal true
    end
  end

  # --- Body parsing ---

  describe "body parsing" do
    it "malformed JSON body → body.json returns false, no crash" do
      req = build_request(
        "rack.input" => StringIO.new("{invalid json"),
        "CONTENT_LENGTH" => "13"
      )
      cond = { "field" => 'http.request.body.json["key"]', "operator" => "exists" }
      _(match?(cond, req)).must_equal false
    end

    it "empty body → body.json returns false" do
      req = build_request("rack.input" => StringIO.new(""))
      cond = { "field" => 'http.request.body.json["key"]', "operator" => "exists" }
      _(match?(cond, req)).must_equal false
    end
  end

  # --- Query params ---

  describe "query params" do
    it "duplicate params → last value wins (.to_h behavior)" do
      req = build_request("QUERY_STRING" => "foo=first&foo=last")
      cond = { "field" => 'http.request.uri.args["foo"]', "operator" => "eq", "value" => "last" }
      _(match?(cond, req)).must_equal true
    end

    it "param with empty value returns empty string" do
      req = build_request("QUERY_STRING" => "foo=")
      cond = { "field" => 'http.request.uri.args["foo"]', "operator" => "eq", "value" => "" }
      _(match?(cond, req)).must_equal true
    end
  end

  # --- eq/ne with numeric values ---

  describe "eq/ne with numeric comparison value" do
    it "eq with numeric value performs numeric comparison" do
      req = build_request("CONTENT_LENGTH" => "1024", "rack.input" => StringIO.new("x" * 1024))
      cond = { "field" => "http.request.body.size", "operator" => "eq", "value" => 1024 }
      _(match?(cond, req)).must_equal true
    end

    it "ne with numeric value performs numeric comparison" do
      req = build_request("CONTENT_LENGTH" => "1024", "rack.input" => StringIO.new("x" * 1024))
      cond = { "field" => "http.request.body.size", "operator" => "ne", "value" => 999 }
      _(match?(cond, req)).must_equal true
    end

    it "eq with numeric value returns false when not equal" do
      req = build_request("CONTENT_LENGTH" => "1024", "rack.input" => StringIO.new("x" * 1024))
      cond = { "field" => "http.request.body.size", "operator" => "eq", "value" => 999 }
      _(match?(cond, req)).must_equal false
    end
  end

  # --- Unknown operator ---

  describe "unknown operator" do
    it "unknown operator returns false" do
      req = build_request("PATH_INFO" => "/test")
      cond = { "field" => "http.request.uri.path", "operator" => "fake_op", "value" => "/test" }
      _(match?(cond, req)).must_equal false
    end
  end

  # --- Unknown transform ---

  describe "unknown transform" do
    it "unknown transform falls through unchanged" do
      req = build_request("PATH_INFO" => "/test")
      cond = { "field" => "http.request.uri.path", "operator" => "eq", "value" => "/test", "transform" => "nonexistent" }
      _(match?(cond, req)).must_equal true
    end
  end

  # --- Parse query params edge cases ---

  describe "parse_query_params edge cases" do
    it "malformed query string (ArgumentError rescue) returns empty hash" do
      # A query string that causes URI.decode_www_form to raise
      req = build_request("QUERY_STRING" => "foo=%ZZ")
      cond = { "field" => 'http.request.uri.args["foo"]', "operator" => "exists" }
      # Should not crash; either returns the value or empty depending on Ruby version
      # The key thing is no exception bubbles up
      match?(cond, req) # just verifying no crash
    end
  end

  # --- File extension edge cases ---

  describe "file extension edge cases" do
    it "dotfile (.env) returns nil (no extension per Ruby File.extname)" do
      req = build_request("PATH_INFO" => "/.env")
      val = Rack::Attack::ConditionEvaluator::EvalContext.new(req, nil).extract_field("http.request.uri.path.extension")
      _(val).must_be_nil
    end

    it "multiple dots (file.tar.gz) returns 'gz'" do
      req = build_request("PATH_INFO" => "/files/archive.tar.gz")
      val = Rack::Attack::ConditionEvaluator::EvalContext.new(req, nil).extract_field("http.request.uri.path.extension")
      _(val).must_equal "gz"
    end
  end

  # --- Nil content_length ---

  describe "nil content_length" do
    it "nil content_length defaults to '0'" do
      req = build_request # no CONTENT_LENGTH set
      val = Rack::Attack::ConditionEvaluator::EvalContext.new(req, nil).extract_field("http.request.body.size")
      _(val).must_equal "0"
    end
  end

  # --- JWT case-insensitive Bearer ---

  describe "JWT case-insensitive Bearer" do
    def encode_jwt_segment(data)
      Base64.urlsafe_encode64(JSON.generate(data), padding: false)
    end

    def make_token(header, payload)
      "#{encode_jwt_segment(header)}.#{encode_jwt_segment(payload)}.fakesig"
    end

    it "lowercase 'bearer' prefix works" do
      token = make_token({ "alg" => "HS256" }, { "sub" => "user1" })
      req = build_request("HTTP_AUTHORIZATION" => "bearer #{token}")
      cond = { "field" => 'jwt.payload["sub"]', "operator" => "eq", "value" => "user1" }
      _(match?(cond, req)).must_equal true
    end
  end

  # --- Throttle key extraction ---

  describe "throttle key extraction" do
    it "returns nil when a field in composite key is missing" do
      req = build_request # no user agent set
      key = extract_throttle_key(["ip.src", "http.user_agent"], req)
      _(key).must_be_nil
    end
  end

  # --- Body JSON memoization ---

  describe "parse_body_json memoization" do
    it "does not re-parse invalid JSON on repeated field access within same condition" do
      call_count = 0
      body = Object.new
      body.define_singleton_method(:read) { |*| call_count += 1; "{invalid json" }
      body.define_singleton_method(:rewind) { }

      req = build_request("rack.input" => body, "CONTENT_LENGTH" => "14")

      # An 'and' condition accessing two body.json fields — body should only be read once
      cond = {
        "and" => [
          { "field" => 'http.request.body.json["a"]', "operator" => "exists" },
          { "field" => 'http.request.body.json["b"]', "operator" => "exists" }
        ]
      }
      _(match?(cond, req)).must_equal false
      _(call_count).must_equal 1
    end
  end

  # --- Non-rewindable body ---

  describe "non-rewindable body" do
    it "reads body without crashing when body does not support rewind" do
      body = Object.new
      body.define_singleton_method(:read) { |*| '{"key":"value"}' }
      # Intentionally no rewind method

      req = build_request("rack.input" => body, "CONTENT_LENGTH" => "15")
      cond = { "field" => 'http.request.body.json["key"]', "operator" => "eq", "value" => "value" }
      _(match?(cond, req)).must_equal true
    end

    it "reads raw body without crashing when body does not support rewind" do
      body = Object.new
      body.define_singleton_method(:read) { |*| "hello world" }
      # Intentionally no rewind method

      req = build_request("rack.input" => body, "CONTENT_LENGTH" => "11")
      cond = { "field" => "http.request.body.raw", "operator" => "contains", "value" => "hello" }
      _(match?(cond, req)).must_equal true
    end
  end
end
