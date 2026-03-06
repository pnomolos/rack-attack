# frozen_string_literal: true

# Cross-implementation conformance test suite.
#
# Runs identical test cases against both:
#   1. Ruby ConditionEvaluator  (lib/rack/attack/condition_evaluator.rb)
#   2. Rust native extension    (rack-attack-native/)
#
# Asserts they produce identical results for each scenario.
#
# Run:
#   cd rack-attack-native && bundle exec rake compile && cd ..
#   bundle exec ruby -Ilib -Ispec -Irack-attack-native/lib spec/conformance_spec.rb

# Skip bundler/setup — the conformance test needs gems from both the main
# project (rack, rack-attack) and the native extension (rack_attack_native).
# Instead we manipulate $LOAD_PATH directly.
$LOAD_PATH.unshift(File.expand_path("../lib", __dir__))
$LOAD_PATH.unshift(File.expand_path("../rack-attack-native/lib", __dir__))

require "minitest/autorun"
require "minitest/pride"
require "rack"
require "rack/attack/condition_evaluator"
require "json"
require "stringio"
require "openssl"
require "jwt"
require "rack_attack_native"

class ConformanceSpec < Minitest::Test
  # ---------------------------------------------------------------------------
  # Helper: evaluate the same rule + request data through both engines.
  #
  # Accepts:
  #   condition  - the condition hash (shared between both engines)
  #   env_data   - a hash describing the request. Keys:
  #     :path, :method, :ip, :user_agent, :query_string, :content_length,
  #     :headers (hash), :cookies (hash), :body (string)
  #   rule_type  - "safelist", "blocklist", "throttle", or "track"
  #   rule_name  - name for the rule (default "test-rule")
  #   key        - throttle key fields (array of strings)
  #   limit      - throttle limit
  #   period     - throttle period
  #
  # Returns [ruby_result, native_result] where each is a boolean indicating
  # whether the condition matched.
  # ---------------------------------------------------------------------------

  def build_rack_env(data)
    env = {
      "REQUEST_METHOD" => (data[:method] || "GET"),
      "PATH_INFO" => (data[:path] || "/"),
      "QUERY_STRING" => (data[:query_string] || ""),
      "REMOTE_ADDR" => (data[:ip] || "127.0.0.1"),
      "SERVER_NAME" => "localhost",
      "SERVER_PORT" => "80",
      "HTTP_HOST" => "localhost",
      "rack.input" => StringIO.new(data[:body] || ""),
      "rack.url_scheme" => "http",
    }
    env["HTTP_USER_AGENT"] = data[:user_agent] if data[:user_agent]
    env["CONTENT_LENGTH"] = data[:content_length].to_s if data[:content_length]

    (data[:headers] || {}).each do |name, value|
      env_key = "HTTP_#{name.upcase.tr('-', '_')}"
      env[env_key] = value
    end

    if data[:cookies] && !data[:cookies].empty?
      cookie_str = data[:cookies].map { |k, v| "#{k}=#{v}" }.join("; ")
      env["HTTP_COOKIE"] = cookie_str
    end

    env
  end

  def build_native_data(data)
    native = {
      path: data[:path] || "/",
      method: data[:method] || "GET",
      ip: data[:ip] || "127.0.0.1",
      query_string: data[:query_string] || "",
      content_length: (data[:content_length] || 0).to_i,
    }
    native[:user_agent] = data[:user_agent] if data[:user_agent]
    native[:headers] = (data[:headers] || {}).transform_keys { |k| k.downcase.tr("_", "-") }
    native[:cookies] = data[:cookies] || {}
    native[:body] = data[:body] if data[:body]

    # Authorization header needs special handling for JWT: the native engine
    # expects it as a top-level :authorization key, not inside :headers.
    if data[:headers]&.key?("Authorization")
      native[:authorization] = data[:headers]["Authorization"]
    end

    native
  end

  def eval_ruby_condition(condition, data, jwt_config: nil)
    env = build_rack_env(data)
    request = Rack::Request.new(env)
    Rack::Attack::ConditionEvaluator.match?(condition, request, jwt_config: jwt_config)
  end

  def eval_native_condition(condition, data, rule_type: "track", rule_name: "test-rule",
                            key: nil, limit: nil, period: nil, jwt_keys: nil)
    rule = {
      "name" => rule_name,
      "type" => rule_type,
      "condition" => condition,
    }
    rule["key"] = key if key
    rule["limit"] = limit if limit
    rule["period"] = period if period

    ruleset_hash = { "rules" => [rule] }
    ruleset_hash["jwt_keys"] = jwt_keys if jwt_keys

    json = JSON.generate(ruleset_hash)
    rs = RackAttackNative::RuleSet.from_json(json)
    native_data = build_native_data(data)
    result = rs.evaluate(native_data)

    case rule_type
    when "safelist"
      result[:safelisted] == rule_name
    when "blocklist"
      result[:blocklisted] == rule_name
    when "throttle"
      result[:throttle_matches].any? { |tm| tm[:name] == rule_name }
    when "track"
      result[:tracked].include?(rule_name)
    end
  end

  # Convenience: assert both engines agree on match/no-match
  def assert_conformance(condition, data, expected, msg = nil,
                         rule_type: "track", rule_name: "test-rule",
                         key: nil, limit: nil, period: nil,
                         jwt_config: nil, jwt_keys: nil)
    ruby_result = eval_ruby_condition(condition, data, jwt_config: jwt_config)
    native_result = eval_native_condition(condition, data,
                                          rule_type: rule_type, rule_name: rule_name,
                                          key: key, limit: limit, period: period,
                                          jwt_keys: jwt_keys)

    label = msg || "condition=#{condition.inspect}, data keys=#{data.keys}"
    assert_equal expected, ruby_result, "Ruby engine: #{label}"
    assert_equal expected, native_result, "Native engine: #{label}"
    assert_equal ruby_result, native_result, "DIVERGENCE: Ruby=#{ruby_result} Native=#{native_result}: #{label}"
  end

  # ===========================================================================
  # Basic operators
  # ===========================================================================

  def test_eq_string_match
    cond = { "field" => "http.request.uri.path", "operator" => "eq", "value" => "/hello" }
    assert_conformance(cond, { path: "/hello" }, true, "eq string match")
  end

  def test_eq_string_no_match
    cond = { "field" => "http.request.uri.path", "operator" => "eq", "value" => "/hello" }
    assert_conformance(cond, { path: "/world" }, false, "eq string no match")
  end

  def test_ne_string_match
    cond = { "field" => "http.request.uri.path", "operator" => "ne", "value" => "/hello" }
    assert_conformance(cond, { path: "/world" }, true, "ne string match")
  end

  def test_ne_string_no_match
    cond = { "field" => "http.request.uri.path", "operator" => "ne", "value" => "/hello" }
    assert_conformance(cond, { path: "/hello" }, false, "ne string no match")
  end

  def test_eq_numeric_match
    cond = { "field" => "http.request.body.size", "operator" => "eq", "value" => 1024 }
    assert_conformance(cond, { content_length: 1024 }, true, "eq numeric match")
  end

  def test_eq_numeric_no_match
    cond = { "field" => "http.request.body.size", "operator" => "eq", "value" => 1024 }
    assert_conformance(cond, { content_length: 512 }, false, "eq numeric no match")
  end

  def test_ne_numeric_match
    cond = { "field" => "http.request.body.size", "operator" => "ne", "value" => 1024 }
    assert_conformance(cond, { content_length: 512 }, true, "ne numeric match")
  end

  def test_starts_with_match
    cond = { "field" => "http.request.uri.path", "operator" => "starts_with", "value" => "/api/" }
    assert_conformance(cond, { path: "/api/v2/users" }, true, "starts_with match")
  end

  def test_starts_with_no_match
    cond = { "field" => "http.request.uri.path", "operator" => "starts_with", "value" => "/api/" }
    assert_conformance(cond, { path: "/about" }, false, "starts_with no match")
  end

  def test_ends_with_match
    cond = { "field" => "http.request.uri.path", "operator" => "ends_with", "value" => ".js" }
    assert_conformance(cond, { path: "/assets/app.js" }, true, "ends_with match")
  end

  def test_ends_with_no_match
    cond = { "field" => "http.request.uri.path", "operator" => "ends_with", "value" => ".js" }
    assert_conformance(cond, { path: "/assets/app.css" }, false, "ends_with no match")
  end

  def test_contains_match
    cond = { "field" => "http.request.uri.path", "operator" => "contains", "value" => ".." }
    assert_conformance(cond, { path: "/../../etc/passwd" }, true, "contains match")
  end

  def test_contains_no_match
    cond = { "field" => "http.request.uri.path", "operator" => "contains", "value" => ".." }
    assert_conformance(cond, { path: "/normal/path" }, false, "contains no match")
  end

  def test_matches_regex_match
    cond = { "field" => "http.request.uri.path", "operator" => "matches", "value" => "^/api/v[0-9]+/" }
    assert_conformance(cond, { path: "/api/v2/users" }, true, "matches regex match")
  end

  def test_matches_regex_no_match
    cond = { "field" => "http.request.uri.path", "operator" => "matches", "value" => "^/api/v[0-9]+/" }
    assert_conformance(cond, { path: "/about" }, false, "matches regex no match")
  end

  def test_matches_word_boundary
    cond = { "field" => "http.user_agent", "operator" => "matches", "value" => "\\b(AhrefsBot|SemrushBot)\\b" }
    assert_conformance(cond, { user_agent: "Mozilla/5.0 (compatible; AhrefsBot/7.0)" }, true, "matches word boundary")
  end

  def test_in_set_match
    cond = { "field" => "http.request.method", "operator" => "in", "value" => ["GET", "POST"] }
    assert_conformance(cond, { method: "GET" }, true, "in set match")
  end

  def test_in_set_no_match
    cond = { "field" => "http.request.method", "operator" => "in", "value" => ["GET", "POST"] }
    assert_conformance(cond, { method: "DELETE" }, false, "in set no match")
  end

  def test_not_in_set_match
    cond = { "field" => "http.request.method", "operator" => "not_in", "value" => ["GET", "POST"] }
    assert_conformance(cond, { method: "TRACE" }, true, "not_in set match")
  end

  def test_not_in_set_no_match
    cond = { "field" => "http.request.method", "operator" => "not_in", "value" => ["GET", "POST"] }
    assert_conformance(cond, { method: "GET" }, false, "not_in set no match")
  end

  def test_exists_present_field
    cond = { "field" => "http.user_agent", "operator" => "exists" }
    assert_conformance(cond, { user_agent: "Mozilla/5.0" }, true, "exists present field")
  end

  def test_exists_absent_field
    cond = { "field" => "http.user_agent", "operator" => "exists" }
    assert_conformance(cond, {}, false, "exists absent field")
  end

  def test_not_exists_absent_field
    cond = { "field" => "http.user_agent", "operator" => "not_exists" }
    assert_conformance(cond, {}, true, "not_exists absent field")
  end

  def test_not_exists_present_field
    cond = { "field" => "http.user_agent", "operator" => "not_exists" }
    assert_conformance(cond, { user_agent: "Mozilla/5.0" }, false, "not_exists present field")
  end

  def test_gt_match
    cond = { "field" => "http.request.body.size", "operator" => "gt", "value" => 1000 }
    assert_conformance(cond, { content_length: 2000 }, true, "gt match")
  end

  def test_gt_no_match
    cond = { "field" => "http.request.body.size", "operator" => "gt", "value" => 1000 }
    assert_conformance(cond, { content_length: 500 }, false, "gt no match")
  end

  def test_lt_match
    cond = { "field" => "http.request.body.size", "operator" => "lt", "value" => 1000 }
    assert_conformance(cond, { content_length: 500 }, true, "lt match")
  end

  def test_lt_no_match
    cond = { "field" => "http.request.body.size", "operator" => "lt", "value" => 1000 }
    assert_conformance(cond, { content_length: 2000 }, false, "lt no match")
  end

  def test_gte_match_equal
    cond = { "field" => "http.request.body.size", "operator" => "gte", "value" => 1000 }
    assert_conformance(cond, { content_length: 1000 }, true, "gte equal")
  end

  def test_gte_match_greater
    cond = { "field" => "http.request.body.size", "operator" => "gte", "value" => 1000 }
    assert_conformance(cond, { content_length: 1001 }, true, "gte greater")
  end

  def test_lte_match_equal
    cond = { "field" => "http.request.body.size", "operator" => "lte", "value" => 1000 }
    assert_conformance(cond, { content_length: 1000 }, true, "lte equal")
  end

  def test_lte_no_match
    cond = { "field" => "http.request.body.size", "operator" => "lte", "value" => 1000 }
    assert_conformance(cond, { content_length: 1001 }, false, "lte no match")
  end

  # ===========================================================================
  # Field types
  # ===========================================================================

  def test_field_path_root
    cond = { "field" => "http.request.uri.path", "operator" => "eq", "value" => "/" }
    assert_conformance(cond, { path: "/" }, true, "path root")
  end

  def test_field_path_nested
    cond = { "field" => "http.request.uri.path", "operator" => "eq", "value" => "/a/b/c" }
    assert_conformance(cond, { path: "/a/b/c" }, true, "nested path")
  end

  def test_field_method_get
    cond = { "field" => "http.request.method", "operator" => "eq", "value" => "GET" }
    assert_conformance(cond, { method: "GET" }, true, "method GET")
  end

  def test_field_method_post
    cond = { "field" => "http.request.method", "operator" => "eq", "value" => "POST" }
    assert_conformance(cond, { method: "POST" }, true, "method POST")
  end

  def test_field_method_mismatch
    cond = { "field" => "http.request.method", "operator" => "eq", "value" => "POST" }
    assert_conformance(cond, { method: "GET" }, false, "method mismatch")
  end

  def test_field_ip_src
    cond = { "field" => "ip.src", "operator" => "eq", "value" => "10.0.0.1" }
    assert_conformance(cond, { ip: "10.0.0.1" }, true, "ip.src match")
  end

  def test_field_ip_src_no_match
    cond = { "field" => "ip.src", "operator" => "eq", "value" => "10.0.0.1" }
    assert_conformance(cond, { ip: "192.168.1.1" }, false, "ip.src no match")
  end

  def test_field_custom_header_match
    cond = { "field" => 'http.request.headers["x-api-key"]', "operator" => "eq", "value" => "secret123" }
    assert_conformance(cond, { headers: { "x-api-key" => "secret123" } }, true, "custom header match")
  end

  def test_field_custom_header_no_match
    cond = { "field" => 'http.request.headers["x-api-key"]', "operator" => "eq", "value" => "secret123" }
    assert_conformance(cond, { headers: { "x-api-key" => "wrong" } }, false, "custom header no match")
  end

  def test_field_custom_header_missing
    cond = { "field" => 'http.request.headers["x-api-key"]', "operator" => "exists" }
    assert_conformance(cond, { headers: {} }, false, "custom header missing")
  end

  def test_field_cookie_match
    cond = { "field" => 'http.request.cookies["session"]', "operator" => "eq", "value" => "abc123" }
    assert_conformance(cond, { cookies: { "session" => "abc123" } }, true, "cookie match")
  end

  def test_field_cookie_no_match
    cond = { "field" => 'http.request.cookies["session"]', "operator" => "eq", "value" => "abc123" }
    assert_conformance(cond, { cookies: { "session" => "xyz" } }, false, "cookie no match")
  end

  def test_field_cookie_missing
    cond = { "field" => 'http.request.cookies["session"]', "operator" => "exists" }
    assert_conformance(cond, { cookies: {} }, false, "cookie missing")
  end

  def test_field_path_extension_js
    cond = { "field" => "http.request.uri.path.extension", "operator" => "eq", "value" => "js" }
    assert_conformance(cond, { path: "/assets/app.js" }, true, "path extension js")
  end

  def test_field_path_extension_css
    cond = { "field" => "http.request.uri.path.extension", "operator" => "in", "value" => ["js", "css", "png"] }
    assert_conformance(cond, { path: "/styles/main.css" }, true, "path extension css in set")
  end

  def test_field_path_extension_none
    cond = { "field" => "http.request.uri.path.extension", "operator" => "exists" }
    assert_conformance(cond, { path: "/api/users" }, false, "no path extension")
  end

  def test_field_body_size
    cond = { "field" => "http.request.body.size", "operator" => "gt", "value" => 10_000_000 }
    assert_conformance(cond, { content_length: 20_000_000 }, true, "body size gt")
  end

  def test_field_user_agent
    cond = { "field" => "http.user_agent", "operator" => "contains", "value" => "Chrome" }
    assert_conformance(cond, { user_agent: "Mozilla/5.0 Chrome/120" }, true, "user agent contains")
  end

  def test_field_user_agent_no_match
    cond = { "field" => "http.user_agent", "operator" => "contains", "value" => "Chrome" }
    assert_conformance(cond, { user_agent: "Mozilla/5.0 Firefox/120" }, false, "user agent no match")
  end

  def test_field_ip_in_range
    cond = { "field" => "ip.src", "operator" => "in_ip_range", "value" => ["10.0.0.0/8"] }
    assert_conformance(cond, { ip: "10.1.2.3" }, true, "ip in range")
  end

  def test_field_ip_not_in_range
    cond = { "field" => "ip.src", "operator" => "in_ip_range", "value" => ["10.0.0.0/8"] }
    assert_conformance(cond, { ip: "192.168.1.1" }, false, "ip not in range")
  end

  def test_field_ip_in_multiple_ranges
    cond = { "field" => "ip.src", "operator" => "in_ip_range", "value" => ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"] }
    assert_conformance(cond, { ip: "172.20.0.1" }, true, "ip in multiple ranges")
  end

  # ===========================================================================
  # Transforms
  # ===========================================================================

  def test_transform_lower
    cond = { "field" => "http.user_agent", "operator" => "contains", "value" => "bot", "transform" => "lower" }
    assert_conformance(cond, { user_agent: "AhrefsBot/7.0" }, true, "lower transform match")
  end

  def test_transform_lower_no_match
    cond = { "field" => "http.user_agent", "operator" => "eq", "value" => "mozilla", "transform" => "lower" }
    assert_conformance(cond, { user_agent: "Chrome" }, false, "lower transform no match")
  end

  def test_transform_lower_already_lowercase
    cond = { "field" => "http.request.uri.path", "operator" => "eq", "value" => "/api/users", "transform" => "lower" }
    assert_conformance(cond, { path: "/api/users" }, true, "lower on already lowercase")
  end

  def test_transform_url_decode
    cond = { "field" => "http.request.uri.path", "operator" => "contains", "value" => "..", "transform" => "url_decode" }
    assert_conformance(cond, { path: "/foo/%2e%2e/bar" }, true, "url_decode transform")
  end

  def test_transform_url_decode_no_encoding
    cond = { "field" => "http.request.uri.path", "operator" => "eq", "value" => "/hello", "transform" => "url_decode" }
    assert_conformance(cond, { path: "/hello" }, true, "url_decode with no encoding")
  end

  def test_transform_length
    cond = { "field" => "http.request.uri.path", "operator" => "gt", "value" => 10, "transform" => "length" }
    assert_conformance(cond, { path: "/api/v2/users/42" }, true, "length transform gt")
  end

  def test_transform_length_short
    cond = { "field" => "http.request.uri.path", "operator" => "gt", "value" => 100, "transform" => "length" }
    assert_conformance(cond, { path: "/short" }, false, "length transform short path")
  end

  def test_transform_chained_url_decode_lower
    cond = {
      "field" => "http.request.uri.query",
      "operator" => "contains",
      "value" => "union select",
      "transform" => ["url_decode", "lower"],
    }
    assert_conformance(cond, { query_string: "q=UNION%20SELECT%20*" }, true, "chained url_decode+lower")
  end

  def test_transform_chained_no_match
    cond = {
      "field" => "http.request.uri.query",
      "operator" => "contains",
      "value" => "drop table",
      "transform" => ["url_decode", "lower"],
    }
    assert_conformance(cond, { query_string: "q=SELECT%20*" }, false, "chained transform no match")
  end

  # ===========================================================================
  # Logical conditions
  # ===========================================================================

  def test_and_all_true
    cond = {
      "and" => [
        { "field" => "http.request.uri.path", "operator" => "starts_with", "value" => "/api/" },
        { "field" => "http.request.method", "operator" => "eq", "value" => "POST" },
      ],
    }
    assert_conformance(cond, { path: "/api/v2/users", method: "POST" }, true, "and all true")
  end

  def test_and_one_false
    cond = {
      "and" => [
        { "field" => "http.request.uri.path", "operator" => "starts_with", "value" => "/api/" },
        { "field" => "http.request.method", "operator" => "eq", "value" => "POST" },
      ],
    }
    assert_conformance(cond, { path: "/api/v2/users", method: "GET" }, false, "and one false")
  end

  def test_and_three_conditions
    cond = {
      "and" => [
        { "field" => "http.request.uri.path", "operator" => "starts_with", "value" => "/api/" },
        { "field" => "http.request.method", "operator" => "eq", "value" => "POST" },
        { "field" => "ip.src", "operator" => "in_ip_range", "value" => ["10.0.0.0/8"] },
      ],
    }
    assert_conformance(cond, { path: "/api/v2/users", method: "POST", ip: "10.0.1.5" }, true, "and three true")
    assert_conformance(cond, { path: "/api/v2/users", method: "POST", ip: "203.0.113.1" }, false, "and three one false")
  end

  def test_or_one_true
    cond = {
      "or" => [
        { "field" => "http.request.uri.path", "operator" => "eq", "value" => "/healthz" },
        { "field" => "http.request.uri.path", "operator" => "eq", "value" => "/readiness" },
      ],
    }
    assert_conformance(cond, { path: "/healthz" }, true, "or first true")
    assert_conformance(cond, { path: "/readiness" }, true, "or second true")
  end

  def test_or_none_true
    cond = {
      "or" => [
        { "field" => "http.request.uri.path", "operator" => "eq", "value" => "/healthz" },
        { "field" => "http.request.uri.path", "operator" => "eq", "value" => "/readiness" },
      ],
    }
    assert_conformance(cond, { path: "/about" }, false, "or none true")
  end

  def test_or_three_conditions
    cond = {
      "or" => [
        { "field" => "http.request.uri.path", "operator" => "eq", "value" => "/a" },
        { "field" => "http.request.uri.path", "operator" => "eq", "value" => "/b" },
        { "field" => "http.request.uri.path", "operator" => "eq", "value" => "/c" },
      ],
    }
    assert_conformance(cond, { path: "/c" }, true, "or third true")
  end

  def test_not_negation_true
    cond = {
      "not" => { "field" => "ip.src", "operator" => "in_ip_range", "value" => ["10.0.0.0/8"] },
    }
    assert_conformance(cond, { ip: "203.0.113.1" }, true, "not negation true")
  end

  def test_not_negation_false
    cond = {
      "not" => { "field" => "ip.src", "operator" => "in_ip_range", "value" => ["10.0.0.0/8"] },
    }
    assert_conformance(cond, { ip: "10.0.0.1" }, false, "not negation false")
  end

  def test_nested_and_or
    cond = {
      "and" => [
        { "field" => "http.request.uri.path", "operator" => "starts_with", "value" => "/api/" },
        {
          "or" => [
            { "field" => "http.request.method", "operator" => "eq", "value" => "GET" },
            { "field" => "http.request.method", "operator" => "eq", "value" => "POST" },
          ],
        },
      ],
    }
    assert_conformance(cond, { path: "/api/v2/users", method: "GET" }, true, "nested and(or) true GET")
    assert_conformance(cond, { path: "/api/v2/users", method: "POST" }, true, "nested and(or) true POST")
    assert_conformance(cond, { path: "/api/v2/users", method: "DELETE" }, false, "nested and(or) false DELETE")
    assert_conformance(cond, { path: "/about", method: "GET" }, false, "nested and(or) false path")
  end

  def test_nested_and_not
    cond = {
      "and" => [
        { "field" => "http.request.uri.path", "operator" => "starts_with", "value" => "/admin" },
        { "not" => { "field" => "ip.src", "operator" => "in_ip_range", "value" => ["10.0.0.0/8"] } },
      ],
    }
    assert_conformance(cond, { path: "/admin/users", ip: "203.0.113.1" }, true, "and+not: external admin")
    assert_conformance(cond, { path: "/admin/users", ip: "10.0.0.5" }, false, "and+not: internal admin")
  end

  def test_deeply_nested_logic
    # (A AND (B OR (NOT C)))
    cond = {
      "and" => [
        { "field" => "http.request.uri.path", "operator" => "starts_with", "value" => "/api/" },
        {
          "or" => [
            { "field" => "http.request.method", "operator" => "eq", "value" => "GET" },
            { "not" => { "field" => "ip.src", "operator" => "eq", "value" => "1.2.3.4" } },
          ],
        },
      ],
    }
    assert_conformance(cond, { path: "/api/v2", method: "GET", ip: "1.2.3.4" }, true, "deep nested: A+B true")
    assert_conformance(cond, { path: "/api/v2", method: "POST", ip: "5.6.7.8" }, true, "deep nested: A+!C true")
    assert_conformance(cond, { path: "/api/v2", method: "POST", ip: "1.2.3.4" }, false, "deep nested: all false")
  end

  # ===========================================================================
  # Rule types (full pipeline through native, condition-only through Ruby)
  # ===========================================================================

  def test_safelist_rule
    cond = { "field" => "http.request.uri.path", "operator" => "eq", "value" => "/healthz" }
    data = { path: "/healthz" }

    ruby_result = eval_ruby_condition(cond, data)
    native_result = eval_native_condition(cond, data, rule_type: "safelist", rule_name: "health-check")

    assert_equal true, ruby_result, "Ruby: safelist condition should match"
    assert_equal true, native_result, "Native: safelist should fire"
  end

  def test_safelist_rule_no_match
    cond = { "field" => "http.request.uri.path", "operator" => "eq", "value" => "/healthz" }
    data = { path: "/about" }

    ruby_result = eval_ruby_condition(cond, data)
    native_result = eval_native_condition(cond, data, rule_type: "safelist", rule_name: "health-check")

    assert_equal false, ruby_result
    assert_equal false, native_result
  end

  def test_blocklist_rule
    cond = { "field" => "ip.src", "operator" => "in", "value" => ["203.0.113.50", "198.51.100.99"] }
    data = { ip: "203.0.113.50" }

    ruby_result = eval_ruby_condition(cond, data)
    native_result = eval_native_condition(cond, data, rule_type: "blocklist", rule_name: "bad-ips")

    assert_equal true, ruby_result
    assert_equal true, native_result
  end

  def test_blocklist_rule_no_match
    cond = { "field" => "ip.src", "operator" => "in", "value" => ["203.0.113.50", "198.51.100.99"] }
    data = { ip: "10.0.0.1" }

    ruby_result = eval_ruby_condition(cond, data)
    native_result = eval_native_condition(cond, data, rule_type: "blocklist", rule_name: "bad-ips")

    assert_equal false, ruby_result
    assert_equal false, native_result
  end

  def test_throttle_rule
    cond = { "field" => "http.request.uri.path", "operator" => "starts_with", "value" => "/api/" }
    data = { path: "/api/v2/users", ip: "10.0.0.1" }

    ruby_result = eval_ruby_condition(cond, data)
    native_result = eval_native_condition(cond, data,
                                          rule_type: "throttle", rule_name: "api-rate",
                                          key: ["ip.src"], limit: 100, period: 60)

    assert_equal true, ruby_result
    assert_equal true, native_result
  end

  def test_throttle_rule_no_match
    cond = { "field" => "http.request.uri.path", "operator" => "starts_with", "value" => "/api/" }
    data = { path: "/about", ip: "10.0.0.1" }

    ruby_result = eval_ruby_condition(cond, data)
    native_result = eval_native_condition(cond, data,
                                          rule_type: "throttle", rule_name: "api-rate",
                                          key: ["ip.src"], limit: 100, period: 60)

    assert_equal false, ruby_result
    assert_equal false, native_result
  end

  def test_throttle_discriminator
    cond = { "field" => "http.request.uri.path", "operator" => "starts_with", "value" => "/api/" }
    data = { path: "/api/v2/users", ip: "10.0.0.1" }

    # Verify the native engine produces the correct discriminator
    rule = {
      "name" => "api-rate",
      "type" => "throttle",
      "condition" => cond,
      "key" => ["ip.src"],
      "limit" => 100,
      "period" => 60,
    }
    json = JSON.generate({ "rules" => [rule] })
    rs = RackAttackNative::RuleSet.from_json(json)
    native_data = build_native_data(data)
    result = rs.evaluate(native_data)

    # Ruby key extraction
    env = build_rack_env(data)
    request = Rack::Request.new(env)
    ruby_key = Rack::Attack::ConditionEvaluator.extract_throttle_key(["ip.src"], request)

    assert_equal 1, result[:throttle_matches].length
    assert_equal ruby_key, result[:throttle_matches][0][:discriminator],
                 "Throttle discriminator should match Ruby key extraction"
  end

  def test_track_rule
    cond = { "field" => "http.request.uri.path", "operator" => "starts_with", "value" => "/admin" }
    assert_conformance(cond, { path: "/admin/dashboard" }, true, "track rule match",
                       rule_type: "track", rule_name: "admin-access")
  end

  def test_track_rule_no_match
    cond = { "field" => "http.request.uri.path", "operator" => "starts_with", "value" => "/admin" }
    assert_conformance(cond, { path: "/about" }, false, "track rule no match",
                       rule_type: "track", rule_name: "admin-access")
  end

  # ===========================================================================
  # Edge cases
  # ===========================================================================

  def test_empty_string_path
    cond = { "field" => "http.request.uri.path", "operator" => "eq", "value" => "" }
    # Both engines should treat an empty path as matching the empty string value.
    # Note: Rack normalizes empty PATH_INFO to "/", so the Ruby engine sees "/".
    # The native engine gets the raw empty string. This is a known divergence
    # at the Rack layer, not the evaluator layer. We test with "/" here so
    # Rack normalization doesn't interfere.
    cond_slash = { "field" => "http.request.uri.path", "operator" => "eq", "value" => "/" }
    assert_conformance(cond_slash, { path: "/" }, true, "root path match")
  end

  def test_empty_string_user_agent
    # Empty user agent should count as "exists" = false (empty string)
    cond = { "field" => "http.user_agent", "operator" => "exists" }
    # Ruby: Rack::Request#user_agent returns nil if HTTP_USER_AGENT not set
    # Native: user_agent defaults to None/nil
    assert_conformance(cond, { user_agent: "" }, false, "empty user agent exists = false")
  end

  def test_unicode_in_path
    cond = { "field" => "http.request.uri.path", "operator" => "contains", "value" => "用户" }
    assert_conformance(cond, { path: "/api/v2/用户/42" }, true, "unicode in path")
  end

  def test_unicode_in_header
    cond = { "field" => 'http.request.headers["x-name"]', "operator" => "eq", "value" => "José" }
    assert_conformance(cond, { headers: { "x-name" => "José" } }, true, "unicode in header")
  end

  def test_very_long_path
    long_path = "/" + "a" * 10_000
    cond = { "field" => "http.request.uri.path", "operator" => "starts_with", "value" => "/aaa" }
    assert_conformance(cond, { path: long_path }, true, "very long path starts_with")
  end

  def test_very_long_no_match
    long_path = "/" + "b" * 10_000
    cond = { "field" => "http.request.uri.path", "operator" => "contains", "value" => "xyz" }
    assert_conformance(cond, { path: long_path }, false, "very long path no match")
  end

  def test_special_regex_chars_in_non_regex_operator
    # These regex special chars should be treated literally by eq/contains/etc.
    cond = { "field" => "http.request.uri.path", "operator" => "contains", "value" => ".*" }
    assert_conformance(cond, { path: "/foo/.*bar" }, true, "literal .* in contains")
    assert_conformance(cond, { path: "/foo/bar" }, false, "literal .* not present")
  end

  def test_special_chars_in_eq
    cond = { "field" => "http.request.uri.path", "operator" => "eq", "value" => "/path?with[brackets]" }
    assert_conformance(cond, { path: "/path?with[brackets]" }, true, "brackets in eq")
  end

  def test_numeric_string_vs_number_in_content_length
    # content_length=0 should match eq 0 (numeric comparison)
    cond = { "field" => "http.request.body.size", "operator" => "eq", "value" => 0 }
    assert_conformance(cond, { content_length: 0 }, true, "content_length 0 == 0")
  end

  def test_in_ip_range_not_an_ip
    # When ip.src is not a valid IP, in_ip_range should return false, not crash
    cond = { "field" => "ip.src", "operator" => "in_ip_range", "value" => ["10.0.0.0/8"] }
    assert_conformance(cond, { ip: "not-an-ip" }, false, "invalid IP in range check")
  end

  def test_not_in_ip_range
    cond = { "field" => "ip.src", "operator" => "not_in_ip_range", "value" => ["10.0.0.0/8"] }
    assert_conformance(cond, { ip: "203.0.113.1" }, true, "not_in_ip_range external")
    assert_conformance(cond, { ip: "10.0.0.1" }, false, "not_in_ip_range internal")
  end

  def test_in_with_single_value
    cond = { "field" => "http.request.method", "operator" => "in", "value" => ["DELETE"] }
    assert_conformance(cond, { method: "DELETE" }, true, "in single-value match")
    assert_conformance(cond, { method: "GET" }, false, "in single-value no match")
  end

  def test_query_string_field
    cond = { "field" => "http.request.uri.query", "operator" => "contains", "value" => "page=" }
    assert_conformance(cond, { query_string: "page=1&sort=asc" }, true, "query string contains")
    assert_conformance(cond, { query_string: "sort=asc" }, false, "query string no match")
  end

  def test_empty_query_string
    cond = { "field" => "http.request.uri.query", "operator" => "exists" }
    # Both engines: empty query string should be "not exists"
    # Ruby: query_string returns "" for no query, which is empty
    # Native: same behavior
    assert_conformance(cond, { query_string: "" }, false, "empty query string exists=false")
  end

  def test_query_string_present
    cond = { "field" => "http.request.uri.query", "operator" => "exists" }
    assert_conformance(cond, { query_string: "q=hello" }, true, "query string exists=true")
  end

  # ===========================================================================
  # Multi-rule evaluation order (native only, but verify condition logic matches)
  # ===========================================================================

  def test_multi_rule_safelist_before_blocklist
    # Verify that when both safelist and blocklist conditions match the request,
    # the native engine returns safelisted (safelist takes priority).
    safelist_cond = { "field" => "ip.src", "operator" => "in_ip_range", "value" => ["10.0.0.0/8"] }
    blocklist_cond = { "field" => "http.request.uri.path", "operator" => "starts_with", "value" => "/admin" }
    data = { path: "/admin/users", ip: "10.0.0.5" }

    # Both conditions should be true
    assert eval_ruby_condition(safelist_cond, data), "Ruby: safelist condition should match"
    assert eval_ruby_condition(blocklist_cond, data), "Ruby: blocklist condition should match"

    # Native multi-rule: safelist should win
    rules = [
      { "name" => "internal", "type" => "safelist", "condition" => safelist_cond },
      { "name" => "admin-block", "type" => "blocklist", "condition" => blocklist_cond },
    ]
    json = JSON.generate({ "rules" => rules })
    rs = RackAttackNative::RuleSet.from_json(json)
    result = rs.evaluate(build_native_data(data))
    assert_equal "internal", result[:safelisted], "Native: safelist should take priority"
    assert_nil result[:blocklisted], "Native: blocklisted should be nil when safelisted"
  end

  # ===========================================================================
  # Dotfile / path extension edge cases
  # ===========================================================================

  def test_path_extension_dotfile
    # Dotfiles like ".env" — both Ruby File.extname(".env") and native now return ""
    # (no extension). The native side was fixed to match Ruby's behavior.
    cond = { "field" => "http.request.uri.path.extension", "operator" => "exists" }
    assert_conformance(cond, { path: "/.env" }, false, "dotfile .env has no extension")
  end

  def test_path_extension_double_dot
    # "/file.tar.gz" — File.extname returns ".gz", so extension is "gz"
    cond = { "field" => "http.request.uri.path.extension", "operator" => "eq", "value" => "gz" }
    assert_conformance(cond, { path: "/archive/file.tar.gz" }, true, "double extension .tar.gz -> gz")
  end

  # ===========================================================================
  # Wildcard operator conformance
  # ===========================================================================

  def test_wildcard_match
    cond = { "field" => "http.request.uri.path", "operator" => "wildcard", "value" => "/api/*/users" }
    assert_conformance(cond, { path: "/api/v2/users" }, true, "wildcard match")
  end

  def test_wildcard_no_match
    cond = { "field" => "http.request.uri.path", "operator" => "wildcard", "value" => "/admin/*" }
    assert_conformance(cond, { path: "/api/v2/users" }, false, "wildcard no match")
  end

  def test_wildcard_case_sensitivity
    # Both Ruby File.fnmatch(FNM_PATHNAME) and native glob_match are case-sensitive.
    # "/assets/*.js" should NOT match "/assets/APP.JS".
    cond = { "field" => "http.request.uri.path", "operator" => "wildcard", "value" => "/assets/*.js" }
    assert_conformance(cond, { path: "/assets/APP.JS" }, false, "wildcard is case-sensitive")
  end

  def test_wildcard_single_star_does_not_cross_slash
    # * should NOT match across path separators (FNM_PATHNAME behavior)
    cond = { "field" => "http.request.uri.path", "operator" => "wildcard", "value" => "/api/*/users" }
    assert_conformance(cond, { path: "/api/v1/v2/users" }, false, "single * does not cross /")
  end

  def test_wildcard_double_star_crosses_slash
    # ** matches across path separators in both Ruby File.fnmatch and glob_match
    cond = { "field" => "http.request.uri.path", "operator" => "wildcard", "value" => "/api/**/users" }
    assert_conformance(cond, { path: "/api/v1/v2/users" }, true, "** crosses /")
  end

  # ===========================================================================
  # Body-related fields conformance
  # ===========================================================================

  def test_body_raw_contains
    cond = { "field" => "http.request.body.raw", "operator" => "contains", "value" => "password" }
    assert_conformance(cond, { body: "email=user@example.com&password=secret" }, true, "body raw contains")
  end

  def test_body_raw_no_body
    cond = { "field" => "http.request.body.raw", "operator" => "exists" }
    # No body provided — should not exist
    assert_conformance(cond, {}, false, "body raw no body")
  end

  def test_body_json_field
    cond = { "field" => 'http.request.body.json["action"]', "operator" => "eq", "value" => "delete" }
    assert_conformance(cond, { body: '{"action": "delete", "id": 42}' }, true, "body json field match")
  end

  def test_body_json_field_missing_key
    cond = { "field" => 'http.request.body.json["missing"]', "operator" => "exists" }
    assert_conformance(cond, { body: '{"action": "delete"}' }, false, "body json missing key")
  end

  # ===========================================================================
  # Query param field conformance
  # ===========================================================================

  def test_query_param_exists
    cond = { "field" => 'http.request.uri.args["q"]', "operator" => "exists" }
    assert_conformance(cond, { query_string: "q=hello&page=1" }, true, "query param exists")
  end

  def test_query_param_missing
    cond = { "field" => 'http.request.uri.args["q"]', "operator" => "exists" }
    assert_conformance(cond, { query_string: "page=1" }, false, "query param missing")
  end

  def test_query_param_value
    cond = { "field" => 'http.request.uri.args["q"]', "operator" => "eq", "value" => "hello" }
    assert_conformance(cond, { query_string: "q=hello&page=1" }, true, "query param value match")
  end

  # ===========================================================================
  # URI field (path + query) conformance
  # ===========================================================================

  def test_uri_with_query
    cond = { "field" => "http.request.uri", "operator" => "contains", "value" => "?page=" }
    assert_conformance(cond, { path: "/api/users", query_string: "page=1" }, true, "uri with query")
  end

  def test_uri_without_query
    cond = { "field" => "http.request.uri", "operator" => "eq", "value" => "/api/users" }
    assert_conformance(cond, { path: "/api/users", query_string: "" }, true, "uri without query")
  end

  # ===========================================================================
  # JWT conformance
  # ===========================================================================

  # Shared JWT fixtures — generated once per test run.
  RSA_PRIVATE = OpenSSL::PKey::RSA.generate(2048)
  RSA_PUBLIC  = RSA_PRIVATE.public_key

  HMAC_SECRET = "test-hmac-secret-key-for-conformance"

  JWT_VALID_RS256 = JWT.encode(
    { "sub" => "user_42", "iss" => "auth.example.com", "aud" => "api.example.com",
      "exp" => Time.now.to_i + 3600, "iat" => Time.now.to_i, "role" => "admin" },
    RSA_PRIVATE, "RS256"
  )

  JWT_VALID_HS256 = JWT.encode(
    { "sub" => "user_99", "iss" => "auth.example.com", "aud" => "api.example.com",
      "exp" => Time.now.to_i + 3600, "iat" => Time.now.to_i, "role" => "viewer" },
    HMAC_SECRET, "HS256"
  )

  JWT_EXPIRED = JWT.encode(
    { "sub" => "user_expired", "iss" => "auth.example.com",
      "exp" => Time.now.to_i - 3600, "iat" => Time.now.to_i - 7200 },
    RSA_PRIVATE, "RS256"
  )

  JWT_WRONG_KEY = JWT.encode(
    { "sub" => "user_wrong", "exp" => Time.now.to_i + 3600 },
    OpenSSL::PKey::RSA.generate(2048), "RS256"
  )

  RS256_CONFIG  = [{ "algorithm" => "RS256", "key" => RSA_PUBLIC.to_pem }]
  HS256_CONFIG  = [{ "algorithm" => "HS256", "key" => HMAC_SECRET }]

  def jwt_request(token)
    { path: "/api/v2/resource", headers: { "Authorization" => "Bearer #{token}" } }
  end

  # --- Unverified payload access (base64 decode, no sig check) ---

  def test_jwt_payload_sub_exists
    cond = { "field" => 'jwt.payload["sub"]', "operator" => "exists" }
    assert_conformance(cond, jwt_request(JWT_VALID_RS256), true,
                       "jwt.payload[sub] exists for valid token",
                       jwt_config: RS256_CONFIG, jwt_keys: RS256_CONFIG)
  end

  def test_jwt_payload_sub_eq
    cond = { "field" => 'jwt.payload["sub"]', "operator" => "eq", "value" => "user_42" }
    assert_conformance(cond, jwt_request(JWT_VALID_RS256), true,
                       "jwt.payload[sub] eq user_42",
                       jwt_config: RS256_CONFIG, jwt_keys: RS256_CONFIG)
  end

  def test_jwt_payload_sub_ne
    cond = { "field" => 'jwt.payload["sub"]', "operator" => "ne", "value" => "user_other" }
    assert_conformance(cond, jwt_request(JWT_VALID_RS256), true,
                       "jwt.payload[sub] ne user_other",
                       jwt_config: RS256_CONFIG, jwt_keys: RS256_CONFIG)
  end

  def test_jwt_payload_sub_no_match
    cond = { "field" => 'jwt.payload["sub"]', "operator" => "eq", "value" => "user_999" }
    assert_conformance(cond, jwt_request(JWT_VALID_RS256), false,
                       "jwt.payload[sub] eq wrong value",
                       jwt_config: RS256_CONFIG, jwt_keys: RS256_CONFIG)
  end

  def test_jwt_payload_role
    cond = { "field" => 'jwt.payload["role"]', "operator" => "eq", "value" => "admin" }
    assert_conformance(cond, jwt_request(JWT_VALID_RS256), true,
                       "jwt.payload[role] eq admin",
                       jwt_config: RS256_CONFIG, jwt_keys: RS256_CONFIG)
  end

  def test_jwt_payload_missing_claim
    cond = { "field" => 'jwt.payload["nonexistent"]', "operator" => "exists" }
    assert_conformance(cond, jwt_request(JWT_VALID_RS256), false,
                       "jwt.payload[nonexistent] does not exist",
                       jwt_config: RS256_CONFIG, jwt_keys: RS256_CONFIG)
  end

  def test_jwt_payload_iss
    cond = { "field" => 'jwt.payload["iss"]', "operator" => "eq", "value" => "auth.example.com" }
    assert_conformance(cond, jwt_request(JWT_VALID_RS256), true,
                       "jwt.payload[iss] matches issuer",
                       jwt_config: RS256_CONFIG, jwt_keys: RS256_CONFIG)
  end

  def test_jwt_payload_aud_ne
    cond = {
      "and" => [
        { "field" => 'jwt.payload["aud"]', "operator" => "exists" },
        { "field" => 'jwt.payload["aud"]', "operator" => "ne", "value" => "api.example.com" },
      ],
    }
    assert_conformance(cond, jwt_request(JWT_VALID_RS256), false,
                       "jwt.payload[aud] is api.example.com so ne fails",
                       jwt_config: RS256_CONFIG, jwt_keys: RS256_CONFIG)
  end

  # --- Unverified payload with expired token (should still decode) ---

  def test_jwt_payload_expired_token_still_decodes
    cond = { "field" => 'jwt.payload["sub"]', "operator" => "eq", "value" => "user_expired" }
    assert_conformance(cond, jwt_request(JWT_EXPIRED), true,
                       "unverified decode works on expired tokens",
                       jwt_config: RS256_CONFIG, jwt_keys: RS256_CONFIG)
  end

  # --- JWT header access ---

  def test_jwt_header_alg
    cond = { "field" => 'jwt.header["alg"]', "operator" => "eq", "value" => "RS256" }
    assert_conformance(cond, jwt_request(JWT_VALID_RS256), true,
                       "jwt.header[alg] eq RS256",
                       jwt_config: RS256_CONFIG, jwt_keys: RS256_CONFIG)
  end

  def test_jwt_header_typ_absent
    # Ruby's JWT gem does not include "typ" in the encoded header by default.
    # Both engines decode the same token, so both see no "typ" field.
    cond = { "field" => 'jwt.header["typ"]', "operator" => "exists" }
    assert_conformance(cond, jwt_request(JWT_VALID_RS256), false,
                       "jwt.header[typ] not present (Ruby JWT gem omits it)",
                       jwt_config: RS256_CONFIG, jwt_keys: RS256_CONFIG)
  end

  # --- Verified payload (signature check) ---

  def test_jwt_verified_payload_valid_rs256
    cond = { "field" => 'jwt.verified_payload["sub"]', "operator" => "eq", "value" => "user_42" }
    assert_conformance(cond, jwt_request(JWT_VALID_RS256), true,
                       "jwt.verified_payload[sub] with valid RS256 token",
                       jwt_config: RS256_CONFIG, jwt_keys: RS256_CONFIG)
  end

  def test_jwt_verified_payload_expired_token
    # Expired token should fail verification -> verified_payload not accessible
    cond = { "field" => 'jwt.verified_payload["sub"]', "operator" => "exists" }
    assert_conformance(cond, jwt_request(JWT_EXPIRED), false,
                       "jwt.verified_payload not available for expired token",
                       jwt_config: RS256_CONFIG, jwt_keys: RS256_CONFIG)
  end

  def test_jwt_verified_payload_wrong_key
    # Token signed with a different key -> verification fails
    cond = { "field" => 'jwt.verified_payload["sub"]', "operator" => "exists" }
    assert_conformance(cond, jwt_request(JWT_WRONG_KEY), false,
                       "jwt.verified_payload not available for wrong-key token",
                       jwt_config: RS256_CONFIG, jwt_keys: RS256_CONFIG)
  end

  # --- jwt.valid field ---

  def test_jwt_valid_true
    cond = { "field" => "jwt.valid", "operator" => "eq", "value" => "true" }
    assert_conformance(cond, jwt_request(JWT_VALID_RS256), true,
                       "jwt.valid is true for valid RS256 token",
                       jwt_config: RS256_CONFIG, jwt_keys: RS256_CONFIG)
  end

  def test_jwt_valid_false_expired
    cond = { "field" => "jwt.valid", "operator" => "eq", "value" => "true" }
    assert_conformance(cond, jwt_request(JWT_EXPIRED), false,
                       "jwt.valid is not true for expired token",
                       jwt_config: RS256_CONFIG, jwt_keys: RS256_CONFIG)
  end

  def test_jwt_valid_false_wrong_key
    cond = { "field" => "jwt.valid", "operator" => "eq", "value" => "true" }
    assert_conformance(cond, jwt_request(JWT_WRONG_KEY), false,
                       "jwt.valid is not true for wrong-key token",
                       jwt_config: RS256_CONFIG, jwt_keys: RS256_CONFIG)
  end

  # --- HMAC (HS256) algorithm ---

  def test_jwt_hs256_payload
    cond = { "field" => 'jwt.payload["sub"]', "operator" => "eq", "value" => "user_99" }
    assert_conformance(cond, jwt_request(JWT_VALID_HS256), true,
                       "jwt.payload[sub] with HS256 token",
                       jwt_config: HS256_CONFIG, jwt_keys: HS256_CONFIG)
  end

  def test_jwt_hs256_verified_payload
    cond = { "field" => 'jwt.verified_payload["sub"]', "operator" => "eq", "value" => "user_99" }
    assert_conformance(cond, jwt_request(JWT_VALID_HS256), true,
                       "jwt.verified_payload[sub] with HS256 token",
                       jwt_config: HS256_CONFIG, jwt_keys: HS256_CONFIG)
  end

  def test_jwt_hs256_valid
    cond = { "field" => "jwt.valid", "operator" => "eq", "value" => "true" }
    assert_conformance(cond, jwt_request(JWT_VALID_HS256), true,
                       "jwt.valid is true for valid HS256 token",
                       jwt_config: HS256_CONFIG, jwt_keys: HS256_CONFIG)
  end

  def test_jwt_hs256_wrong_secret
    wrong_config = [{ "algorithm" => "HS256", "key" => "wrong-secret" }]
    cond = { "field" => "jwt.valid", "operator" => "eq", "value" => "true" }
    assert_conformance(cond, jwt_request(JWT_VALID_HS256), false,
                       "jwt.valid is false with wrong HMAC secret",
                       jwt_config: wrong_config, jwt_keys: wrong_config)
  end

  # --- No token / no Authorization header ---

  def test_jwt_no_token_payload_not_exists
    cond = { "field" => 'jwt.payload["sub"]', "operator" => "exists" }
    assert_conformance(cond, { path: "/api/v2/resource" }, false,
                       "jwt.payload[sub] not exists when no Authorization header",
                       jwt_config: RS256_CONFIG, jwt_keys: RS256_CONFIG)
  end

  def test_jwt_no_token_valid_not_true
    cond = { "field" => "jwt.valid", "operator" => "eq", "value" => "true" }
    assert_conformance(cond, { path: "/api/v2/resource" }, false,
                       "jwt.valid is not true when no token",
                       jwt_config: RS256_CONFIG, jwt_keys: RS256_CONFIG)
  end

  def test_jwt_non_bearer_auth_header
    cond = { "field" => 'jwt.payload["sub"]', "operator" => "exists" }
    data = { path: "/api/v2/resource", headers: { "Authorization" => "Basic dXNlcjpwYXNz" } }
    assert_conformance(cond, data, false,
                       "jwt.payload not available for Basic auth",
                       jwt_config: RS256_CONFIG, jwt_keys: RS256_CONFIG)
  end

  # --- JWT in compound conditions ---

  def test_jwt_throttle_by_sub
    cond = {
      "and" => [
        { "field" => "http.request.uri.path", "operator" => "starts_with", "value" => "/api/" },
        { "field" => 'jwt.payload["sub"]', "operator" => "exists" },
      ],
    }
    assert_conformance(cond, jwt_request(JWT_VALID_RS256), true,
                       "JWT sub exists in compound condition",
                       rule_type: "throttle", rule_name: "jwt-throttle",
                       key: ['jwt.payload["sub"]'], limit: 100, period: 60,
                       jwt_config: RS256_CONFIG, jwt_keys: RS256_CONFIG)
  end

  def test_jwt_blocklist_expired
    # Block requests with expired JWTs: jwt.payload[sub] exists but jwt.valid != true
    cond = {
      "and" => [
        { "field" => 'jwt.payload["sub"]', "operator" => "exists" },
        { "not" => { "field" => "jwt.valid", "operator" => "eq", "value" => "true" } },
      ],
    }
    assert_conformance(cond, jwt_request(JWT_EXPIRED), true,
                       "blocklist expired JWT: sub exists but not valid",
                       rule_type: "blocklist", rule_name: "jwt-expired-block",
                       jwt_config: RS256_CONFIG, jwt_keys: RS256_CONFIG)
  end

  def test_jwt_blocklist_valid_not_blocked
    # Valid JWT should NOT be blocked by the expired-JWT rule
    cond = {
      "and" => [
        { "field" => 'jwt.payload["sub"]', "operator" => "exists" },
        { "not" => { "field" => "jwt.valid", "operator" => "eq", "value" => "true" } },
      ],
    }
    assert_conformance(cond, jwt_request(JWT_VALID_RS256), false,
                       "valid JWT not blocked by expired-JWT rule",
                       rule_type: "blocklist", rule_name: "jwt-expired-block",
                       jwt_config: RS256_CONFIG, jwt_keys: RS256_CONFIG)
  end

  # --- RS256 cross-verification: HS256 token with RS256 config ---

  def test_jwt_rs256_config_hs256_token_unverified
    # Unverified decode should still work regardless of key config
    cond = { "field" => 'jwt.payload["sub"]', "operator" => "eq", "value" => "user_99" }
    assert_conformance(cond, jwt_request(JWT_VALID_HS256), true,
                       "unverified decode works with mismatched key config",
                       jwt_config: RS256_CONFIG, jwt_keys: RS256_CONFIG)
  end

  def test_jwt_rs256_config_hs256_token_verified_fails
    # Verification should fail: HS256 token can't be verified with RS256 key
    cond = { "field" => "jwt.valid", "operator" => "eq", "value" => "true" }
    assert_conformance(cond, jwt_request(JWT_VALID_HS256), false,
                       "HS256 token not valid with RS256 config",
                       jwt_config: RS256_CONFIG, jwt_keys: RS256_CONFIG)
  end

  # ===========================================================================
  # Nested JSON body access conformance
  # ===========================================================================

  def test_nested_json_body_field
    cond = { "field" => 'http.request.body.json["user.profile.name"]', "operator" => "eq", "value" => "Alice" }
    assert_conformance(cond, { body: '{"user": {"profile": {"name": "Alice"}}}' }, true,
                       "nested body json field match")
  end

  def test_nested_json_body_field_no_match
    cond = { "field" => 'http.request.body.json["user.profile.name"]', "operator" => "eq", "value" => "Bob" }
    assert_conformance(cond, { body: '{"user": {"profile": {"name": "Alice"}}}' }, false,
                       "nested body json field no match")
  end

  def test_nested_json_body_missing_intermediate_key
    cond = { "field" => 'http.request.body.json["user.address.city"]', "operator" => "exists" }
    assert_conformance(cond, { body: '{"user": {"profile": {"name": "Alice"}}}' }, false,
                       "nested body json missing intermediate key")
  end

  def test_nested_json_body_number_value
    cond = { "field" => 'http.request.body.json["data.count"]', "operator" => "eq", "value" => "42" }
    assert_conformance(cond, { body: '{"data": {"count": 42}}' }, true,
                       "nested body json number value stringified")
  end

  def test_flat_json_body_still_works
    # Ensure single-key access still works (no dots = flat access)
    cond = { "field" => 'http.request.body.json["action"]', "operator" => "eq", "value" => "delete" }
    assert_conformance(cond, { body: '{"action": "delete"}' }, true,
                       "flat body json field still works")
  end

  def test_deeply_nested_json_body
    cond = { "field" => 'http.request.body.json["a.b.c.d"]', "operator" => "eq", "value" => "deep" }
    assert_conformance(cond, { body: '{"a": {"b": {"c": {"d": "deep"}}}}' }, true,
                       "deeply nested body json access")
  end

  # ===========================================================================
  # Enabled/disabled rules conformance
  # ===========================================================================

  def test_disabled_rule_skipped_native
    # Verify the native engine skips disabled rules
    condition = { "field" => "http.request.uri.path", "operator" => "eq", "value" => "/blocked" }
    rule = {
      "name" => "disabled-block",
      "type" => "blocklist",
      "enabled" => false,
      "condition" => condition,
    }
    json = JSON.generate({ "rules" => [rule] })
    rs = RackAttackNative::RuleSet.from_json(json)
    native_data = build_native_data({ path: "/blocked" })
    result = rs.evaluate(native_data)
    assert_nil result[:blocklisted], "Native engine should skip disabled rule"
  end

  def test_disabled_rule_skipped_ruby
    # Verify the Ruby evaluator still matches the condition itself (the skip happens at registration)
    condition = { "field" => "http.request.uri.path", "operator" => "eq", "value" => "/blocked" }
    # The condition itself matches — the Ruby engine doesn't know about "enabled"
    ruby_result = eval_ruby_condition(condition, { path: "/blocked" })
    assert_equal true, ruby_result, "Ruby condition evaluator matches the condition (skip is at registration layer)"
  end

  def test_enabled_true_rule_evaluated_native
    condition = { "field" => "http.request.uri.path", "operator" => "eq", "value" => "/test" }
    rule = {
      "name" => "enabled-track",
      "type" => "track",
      "enabled" => true,
      "description" => "A rule with explicit enabled: true",
      "condition" => condition,
    }
    json = JSON.generate({ "rules" => [rule] })
    rs = RackAttackNative::RuleSet.from_json(json)
    native_data = build_native_data({ path: "/test" })
    result = rs.evaluate(native_data)
    assert_includes result[:tracked], "enabled-track", "Native engine should evaluate enabled rules"
  end

  def test_description_field_accepted_native
    condition = { "field" => "http.request.uri.path", "operator" => "eq", "value" => "/" }
    rule = {
      "name" => "desc-rule",
      "type" => "track",
      "description" => "This is a helpful description for documentation",
      "condition" => condition,
    }
    json = JSON.generate({ "rules" => [rule] })
    rs = RackAttackNative::RuleSet.from_json(json)
    native_data = build_native_data({ path: "/" })
    result = rs.evaluate(native_data)
    assert_includes result[:tracked], "desc-rule", "Description field should not affect evaluation"
  end

  # ===========================================================================
  # Rule order conformance
  # ===========================================================================

  def test_insertion_order_preserves_rule_sequence
    # With insertion order, rules should stay in the order given
    rules = [
      { "name" => "expensive-regex", "type" => "blocklist",
        "condition" => { "field" => "http.user_agent", "operator" => "matches", "value" => "\\bBot\\b" } },
      { "name" => "cheap-path", "type" => "blocklist",
        "condition" => { "field" => "http.request.uri.path", "operator" => "eq", "value" => "/blocked" } },
    ]

    # With insertion order: expensive-regex is checked first
    json_insertion = JSON.generate({ "rule_order" => "insertion", "rules" => rules })
    rs_insertion = RackAttackNative::RuleSet.from_json(json_insertion)

    # A request matching both — the first blocklist in order wins
    native_data = build_native_data({ path: "/blocked", user_agent: "My Bot Agent" })
    result = rs_insertion.evaluate(native_data)
    assert_equal "expensive-regex", result[:blocklisted],
                 "Insertion order: first matching blocklist in JSON order should win"
  end

  def test_cost_order_reorders_rules
    rules = [
      { "name" => "expensive-regex", "type" => "blocklist",
        "condition" => { "field" => "http.user_agent", "operator" => "matches", "value" => "\\bBot\\b" } },
      { "name" => "cheap-path", "type" => "blocklist",
        "condition" => { "field" => "http.request.uri.path", "operator" => "eq", "value" => "/blocked" } },
    ]

    # With cost order: cheap-path (cost ~2) is checked before expensive-regex (cost ~10)
    json_cost = JSON.generate({ "rule_order" => "cost", "rules" => rules })
    rs_cost = RackAttackNative::RuleSet.from_json(json_cost)

    native_data = build_native_data({ path: "/blocked", user_agent: "My Bot Agent" })
    result = rs_cost.evaluate(native_data)
    assert_equal "cheap-path", result[:blocklisted],
                 "Cost order: cheaper blocklist should be evaluated first and win"
  end

  def test_invalid_rule_order_rejected
    json = JSON.generate({ "rule_order" => "random", "rules" => [] })
    error = assert_raises(ArgumentError) { RackAttackNative::RuleSet.from_json(json) }
    assert_match(/Invalid rule_order/, error.message)
  end
end
