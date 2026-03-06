# frozen_string_literal: true

require_relative "../spec_helper"
require "json"
require "stringio"

describe Rack::Attack::ConditionEvaluator do
  # URL-safe Base64 encode without the base64 gem (removed in Ruby 4.0)
  def urlsafe_encode64_no_pad(str)
    [str].pack("m0").tr("+/", "-_").delete("=")
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

  describe ".match?" do
    it "returns true for nil condition" do
      request = make_request
      _(Rack::Attack::ConditionEvaluator.match?(nil, request)).must_equal true
    end

    describe "field extraction" do
      it "extracts ip.src" do
        request = make_request("REMOTE_ADDR" => "10.0.0.1")
        condition = { "field" => "ip.src", "operator" => "eq", "value" => "10.0.0.1" }
        _(Rack::Attack::ConditionEvaluator.match?(condition, request)).must_equal true
      end

      it "extracts http.request.uri.path" do
        request = make_request("PATH_INFO" => "/api/users")
        condition = { "field" => "http.request.uri.path", "operator" => "eq", "value" => "/api/users" }
        _(Rack::Attack::ConditionEvaluator.match?(condition, request)).must_equal true
      end

      it "extracts http.request.method" do
        request = make_request("REQUEST_METHOD" => "POST")
        condition = { "field" => "http.request.method", "operator" => "eq", "value" => "POST" }
        _(Rack::Attack::ConditionEvaluator.match?(condition, request)).must_equal true
      end

      it "extracts http.user_agent" do
        request = make_request("HTTP_USER_AGENT" => "Mozilla/5.0")
        condition = { "field" => "http.user_agent", "operator" => "starts_with", "value" => "Mozilla" }
        _(Rack::Attack::ConditionEvaluator.match?(condition, request)).must_equal true
      end

      it "extracts http.host" do
        request = make_request("HTTP_HOST" => "api.example.com")
        condition = { "field" => "http.host", "operator" => "eq", "value" => "api.example.com" }
        _(Rack::Attack::ConditionEvaluator.match?(condition, request)).must_equal true
      end

      it "extracts http.request.uri.query" do
        request = make_request("QUERY_STRING" => "foo=bar&baz=qux")
        condition = { "field" => "http.request.uri.query", "operator" => "contains", "value" => "foo=bar" }
        _(Rack::Attack::ConditionEvaluator.match?(condition, request)).must_equal true
      end

      it "extracts http.request.uri with query string" do
        request = make_request("PATH_INFO" => "/search", "QUERY_STRING" => "q=test")
        condition = { "field" => "http.request.uri", "operator" => "eq", "value" => "/search?q=test" }
        _(Rack::Attack::ConditionEvaluator.match?(condition, request)).must_equal true
      end

      it "extracts http.request.uri without query string" do
        request = make_request("PATH_INFO" => "/search", "QUERY_STRING" => "")
        condition = { "field" => "http.request.uri", "operator" => "eq", "value" => "/search" }
        _(Rack::Attack::ConditionEvaluator.match?(condition, request)).must_equal true
      end

      it "extracts http.request.uri.path.extension" do
        request = make_request("PATH_INFO" => "/assets/style.css")
        condition = { "field" => "http.request.uri.path.extension", "operator" => "eq", "value" => "css" }
        _(Rack::Attack::ConditionEvaluator.match?(condition, request)).must_equal true
      end

      it "returns nil for path without extension" do
        request = make_request("PATH_INFO" => "/api/users")
        condition = { "field" => "http.request.uri.path.extension", "operator" => "exists" }
        _(Rack::Attack::ConditionEvaluator.match?(condition, request)).must_equal false
      end

      it "extracts http.request.body.size" do
        request = make_request("CONTENT_LENGTH" => "1024")
        condition = { "field" => "http.request.body.size", "operator" => "gt", "value" => 500 }
        _(Rack::Attack::ConditionEvaluator.match?(condition, request)).must_equal true
      end

      it "extracts http.request.headers" do
        request = make_request("HTTP_X_API_KEY" => "secret123")
        condition = { "field" => 'http.request.headers["x-api-key"]', "operator" => "eq", "value" => "secret123" }
        _(Rack::Attack::ConditionEvaluator.match?(condition, request)).must_equal true
      end

      it "extracts http.request.cookies" do
        request = make_request("HTTP_COOKIE" => "_session_id=abc123")
        condition = { "field" => 'http.request.cookies["_session_id"]', "operator" => "eq", "value" => "abc123" }
        _(Rack::Attack::ConditionEvaluator.match?(condition, request)).must_equal true
      end

      it "extracts http.request.uri.args" do
        request = make_request("QUERY_STRING" => "page=2&per=10")
        condition = { "field" => 'http.request.uri.args["page"]', "operator" => "eq", "value" => "2" }
        _(Rack::Attack::ConditionEvaluator.match?(condition, request)).must_equal true
      end

      it "extracts http.request.body.json" do
        body = StringIO.new('{"action":"create","name":"test"}')
        request = make_request("rack.input" => body)
        condition = { "field" => 'http.request.body.json["action"]', "operator" => "eq", "value" => "create" }
        _(Rack::Attack::ConditionEvaluator.match?(condition, request)).must_equal true
      end

      it "extracts http.request.body.raw" do
        body = StringIO.new("raw body content")
        request = make_request("rack.input" => body)
        condition = { "field" => "http.request.body.raw", "operator" => "contains", "value" => "raw body" }
        _(Rack::Attack::ConditionEvaluator.match?(condition, request)).must_equal true
      end
    end

    describe "JWT fields" do
      def make_jwt(payload, header = { "alg" => "none", "typ" => "JWT" })
        header_b64 = urlsafe_encode64_no_pad(JSON.generate(header))
        payload_b64 = urlsafe_encode64_no_pad(JSON.generate(payload))
        "#{header_b64}.#{payload_b64}.fake_signature"
      end

      it "extracts jwt.payload claims" do
        token = make_jwt({ "sub" => "user123", "aud" => "api.example.com" })
        request = make_request("HTTP_AUTHORIZATION" => "Bearer #{token}")
        condition = { "field" => 'jwt.payload["sub"]', "operator" => "eq", "value" => "user123" }
        _(Rack::Attack::ConditionEvaluator.match?(condition, request)).must_equal true
      end

      it "extracts jwt.header fields" do
        token = make_jwt({ "sub" => "user123" }, { "alg" => "HS256", "typ" => "JWT" })
        request = make_request("HTTP_AUTHORIZATION" => "Bearer #{token}")
        condition = { "field" => 'jwt.header["alg"]', "operator" => "eq", "value" => "HS256" }
        _(Rack::Attack::ConditionEvaluator.match?(condition, request)).must_equal true
      end

      it "returns nil for missing JWT" do
        request = make_request
        condition = { "field" => 'jwt.payload["sub"]', "operator" => "exists" }
        _(Rack::Attack::ConditionEvaluator.match?(condition, request)).must_equal false
      end

      it "returns nil for invalid JWT" do
        request = make_request("HTTP_AUTHORIZATION" => "Bearer not-a-jwt")
        condition = { "field" => 'jwt.payload["sub"]', "operator" => "exists" }
        _(Rack::Attack::ConditionEvaluator.match?(condition, request)).must_equal false
      end
    end

    describe "operators" do
      it "eq matches equal strings" do
        request = make_request("PATH_INFO" => "/api")
        _(Rack::Attack::ConditionEvaluator.match?(
          { "field" => "http.request.uri.path", "operator" => "eq", "value" => "/api" }, request
        )).must_equal true
      end

      it "eq rejects non-equal strings" do
        request = make_request("PATH_INFO" => "/api")
        _(Rack::Attack::ConditionEvaluator.match?(
          { "field" => "http.request.uri.path", "operator" => "eq", "value" => "/other" }, request
        )).must_equal false
      end

      it "ne matches non-equal strings" do
        request = make_request("PATH_INFO" => "/api")
        _(Rack::Attack::ConditionEvaluator.match?(
          { "field" => "http.request.uri.path", "operator" => "ne", "value" => "/other" }, request
        )).must_equal true
      end

      it "in matches value in array" do
        request = make_request("REQUEST_METHOD" => "POST")
        _(Rack::Attack::ConditionEvaluator.match?(
          { "field" => "http.request.method", "operator" => "in", "value" => ["GET", "POST", "PUT"] }, request
        )).must_equal true
      end

      it "not_in rejects value in array" do
        request = make_request("REQUEST_METHOD" => "DELETE")
        _(Rack::Attack::ConditionEvaluator.match?(
          { "field" => "http.request.method", "operator" => "not_in", "value" => ["GET", "POST"] }, request
        )).must_equal true
      end

      it "contains checks substring" do
        request = make_request("PATH_INFO" => "/api/v1/users")
        _(Rack::Attack::ConditionEvaluator.match?(
          { "field" => "http.request.uri.path", "operator" => "contains", "value" => "v1" }, request
        )).must_equal true
      end

      it "starts_with checks prefix" do
        request = make_request("PATH_INFO" => "/api/users")
        _(Rack::Attack::ConditionEvaluator.match?(
          { "field" => "http.request.uri.path", "operator" => "starts_with", "value" => "/api/" }, request
        )).must_equal true
      end

      it "ends_with checks suffix" do
        request = make_request("PATH_INFO" => "/file.json")
        _(Rack::Attack::ConditionEvaluator.match?(
          { "field" => "http.request.uri.path", "operator" => "ends_with", "value" => ".json" }, request
        )).must_equal true
      end

      it "matches checks regex" do
        request = make_request("PATH_INFO" => "/api/v2/search")
        _(Rack::Attack::ConditionEvaluator.match?(
          { "field" => "http.request.uri.path", "operator" => "matches", "value" => "^/api/v[0-9]+/search$" }, request
        )).must_equal true
      end

      it "wildcard uses fnmatch" do
        request = make_request("PATH_INFO" => "/api/v1/users/123")
        _(Rack::Attack::ConditionEvaluator.match?(
          { "field" => "http.request.uri.path", "operator" => "wildcard", "value" => "/api/*/users/*" }, request
        )).must_equal true
      end

      it "exists checks field presence" do
        request = make_request("HTTP_USER_AGENT" => "TestBot")
        _(Rack::Attack::ConditionEvaluator.match?(
          { "field" => "http.user_agent", "operator" => "exists" }, request
        )).must_equal true
      end

      it "not_exists checks field absence" do
        request = make_request
        _(Rack::Attack::ConditionEvaluator.match?(
          { "field" => "http.user_agent", "operator" => "not_exists" }, request
        )).must_equal true
      end

      it "gt compares numerically" do
        request = make_request("CONTENT_LENGTH" => "2000")
        _(Rack::Attack::ConditionEvaluator.match?(
          { "field" => "http.request.body.size", "operator" => "gt", "value" => 1000 }, request
        )).must_equal true
      end

      it "lt compares numerically" do
        request = make_request("CONTENT_LENGTH" => "500")
        _(Rack::Attack::ConditionEvaluator.match?(
          { "field" => "http.request.body.size", "operator" => "lt", "value" => 1000 }, request
        )).must_equal true
      end

      it "gte compares numerically" do
        request = make_request("CONTENT_LENGTH" => "1000")
        _(Rack::Attack::ConditionEvaluator.match?(
          { "field" => "http.request.body.size", "operator" => "gte", "value" => 1000 }, request
        )).must_equal true
      end

      it "lte compares numerically" do
        request = make_request("CONTENT_LENGTH" => "1000")
        _(Rack::Attack::ConditionEvaluator.match?(
          { "field" => "http.request.body.size", "operator" => "lte", "value" => 1000 }, request
        )).must_equal true
      end

      it "in_ip_range matches CIDR" do
        request = make_request("REMOTE_ADDR" => "10.0.1.5")
        _(Rack::Attack::ConditionEvaluator.match?(
          { "field" => "ip.src", "operator" => "in_ip_range", "value" => ["10.0.0.0/8"] }, request
        )).must_equal true
      end

      it "in_ip_range rejects non-matching IP" do
        request = make_request("REMOTE_ADDR" => "192.168.1.1")
        _(Rack::Attack::ConditionEvaluator.match?(
          { "field" => "ip.src", "operator" => "in_ip_range", "value" => ["10.0.0.0/8"] }, request
        )).must_equal false
      end

      it "not_in_ip_range works" do
        request = make_request("REMOTE_ADDR" => "192.168.1.1")
        _(Rack::Attack::ConditionEvaluator.match?(
          { "field" => "ip.src", "operator" => "not_in_ip_range", "value" => ["10.0.0.0/8"] }, request
        )).must_equal true
      end
    end

    describe "transforms" do
      it "lower transforms field value" do
        request = make_request("HTTP_USER_AGENT" => "AhrefsBot/7.0")
        _(Rack::Attack::ConditionEvaluator.match?(
          { "field" => "http.user_agent", "operator" => "contains", "value" => "ahrefsbot", "transform" => "lower" }, request
        )).must_equal true
      end

      it "upper transforms field value" do
        request = make_request("REQUEST_METHOD" => "get")
        _(Rack::Attack::ConditionEvaluator.match?(
          { "field" => "http.request.method", "operator" => "eq", "value" => "GET", "transform" => "upper" }, request
        )).must_equal true
      end

      it "url_decode transforms field value" do
        request = make_request("QUERY_STRING" => "q=hello%20world%26more")
        _(Rack::Attack::ConditionEvaluator.match?(
          { "field" => "http.request.uri.query", "operator" => "contains", "value" => "hello world", "transform" => "url_decode" }, request
        )).must_equal true
      end

      it "length transforms to string length" do
        request = make_request("HTTP_USER_AGENT" => "Short")
        _(Rack::Attack::ConditionEvaluator.match?(
          { "field" => "http.user_agent", "operator" => "eq", "value" => "5", "transform" => "length" }, request
        )).must_equal true
      end

      it "chains multiple transforms" do
        request = make_request("QUERY_STRING" => "q=HELLO%20WORLD")
        _(Rack::Attack::ConditionEvaluator.match?(
          { "field" => "http.request.uri.query", "operator" => "contains", "value" => "hello world", "transform" => ["url_decode", "lower"] }, request
        )).must_equal true
      end
    end

    describe "logical combinators" do
      it "and requires all conditions" do
        request = make_request("REQUEST_METHOD" => "POST", "PATH_INFO" => "/api/users")
        condition = {
          "and" => [
            { "field" => "http.request.method", "operator" => "eq", "value" => "POST" },
            { "field" => "http.request.uri.path", "operator" => "starts_with", "value" => "/api/" }
          ]
        }
        _(Rack::Attack::ConditionEvaluator.match?(condition, request)).must_equal true
      end

      it "and fails if any condition fails" do
        request = make_request("REQUEST_METHOD" => "GET", "PATH_INFO" => "/api/users")
        condition = {
          "and" => [
            { "field" => "http.request.method", "operator" => "eq", "value" => "POST" },
            { "field" => "http.request.uri.path", "operator" => "starts_with", "value" => "/api/" }
          ]
        }
        _(Rack::Attack::ConditionEvaluator.match?(condition, request)).must_equal false
      end

      it "or matches if any condition matches" do
        request = make_request("PATH_INFO" => "/healthz")
        condition = {
          "or" => [
            { "field" => "http.request.uri.path", "operator" => "eq", "value" => "/healthz" },
            { "field" => "http.request.uri.path", "operator" => "eq", "value" => "/readiness" }
          ]
        }
        _(Rack::Attack::ConditionEvaluator.match?(condition, request)).must_equal true
      end

      it "or fails if no condition matches" do
        request = make_request("PATH_INFO" => "/api")
        condition = {
          "or" => [
            { "field" => "http.request.uri.path", "operator" => "eq", "value" => "/healthz" },
            { "field" => "http.request.uri.path", "operator" => "eq", "value" => "/readiness" }
          ]
        }
        _(Rack::Attack::ConditionEvaluator.match?(condition, request)).must_equal false
      end

      it "not negates a condition" do
        request = make_request("REMOTE_ADDR" => "203.0.113.50")
        condition = {
          "not" => { "field" => "ip.src", "operator" => "in_ip_range", "value" => ["10.0.0.0/8"] }
        }
        _(Rack::Attack::ConditionEvaluator.match?(condition, request)).must_equal true
      end

      it "nested logical combinators work" do
        request = make_request(
          "REQUEST_METHOD" => "POST",
          "PATH_INFO" => "/admin/settings",
          "REMOTE_ADDR" => "203.0.113.50"
        )
        condition = {
          "and" => [
            { "field" => "http.request.uri.path", "operator" => "starts_with", "value" => "/admin" },
            { "not" => { "field" => "ip.src", "operator" => "in_ip_range", "value" => ["10.0.0.0/8"] } }
          ]
        }
        _(Rack::Attack::ConditionEvaluator.match?(condition, request)).must_equal true
      end
    end

    describe "with symbol keys" do
      it "handles symbolized conditions" do
        request = make_request("PATH_INFO" => "/api")
        condition = { field: "http.request.uri.path", operator: "eq", value: "/api" }
        _(Rack::Attack::ConditionEvaluator.match?(condition, request)).must_equal true
      end
    end
  end

  describe ".extract_throttle_key" do
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

    it "extracts single key field" do
      request = make_request("REMOTE_ADDR" => "10.0.0.1")
      key = Rack::Attack::ConditionEvaluator.extract_throttle_key(["ip.src"], request)
      _(key).must_equal "10.0.0.1"
    end

    it "extracts composite key" do
      request = make_request("REMOTE_ADDR" => "10.0.0.1", "HTTP_X_API_KEY" => "key123")
      key = Rack::Attack::ConditionEvaluator.extract_throttle_key(
        ["ip.src", 'http.request.headers["x-api-key"]'], request
      )
      _(key).must_equal "10.0.0.1:key123"
    end

    it "returns nil if any field is missing" do
      request = make_request("REMOTE_ADDR" => "10.0.0.1")
      key = Rack::Attack::ConditionEvaluator.extract_throttle_key(
        ["ip.src", 'http.request.headers["x-api-key"]'], request
      )
      _(key).must_be_nil
    end
  end
end
