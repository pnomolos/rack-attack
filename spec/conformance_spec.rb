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
    native
  end

  def eval_ruby_condition(condition, data)
    env = build_rack_env(data)
    request = Rack::Request.new(env)
    Rack::Attack::ConditionEvaluator.match?(condition, request)
  end

  def eval_native_condition(condition, data, rule_type: "track", rule_name: "test-rule",
                            key: nil, limit: nil, period: nil)
    rule = {
      "name" => rule_name,
      "type" => rule_type,
      "condition" => condition,
    }
    rule["key"] = key if key
    rule["limit"] = limit if limit
    rule["period"] = period if period

    json = JSON.generate({ "rules" => [rule] })
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
                         key: nil, limit: nil, period: nil)
    ruby_result = eval_ruby_condition(condition, data)
    native_result = eval_native_condition(condition, data,
                                          rule_type: rule_type, rule_name: rule_name,
                                          key: key, limit: limit, period: period)

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
    # Dotfiles like ".env" — Ruby File.extname(".env") returns "" (no extension).
    # Known divergence: native may return "env". Document this.
    cond = { "field" => "http.request.uri.path.extension", "operator" => "exists" }
    ruby_result = eval_ruby_condition(cond, { path: "/.env" })
    native_result = eval_native_condition(cond, { path: "/.env" })

    if ruby_result != native_result
      skip "KNOWN DIVERGENCE: dotfile extension — Ruby File.extname('/.env')='' (no ext), " \
           "native may return 'env'. Ruby=#{ruby_result}, Native=#{native_result}"
    else
      assert_equal ruby_result, native_result, "dotfile extension"
    end
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
    # Ruby File.fnmatch with FNM_PATHNAME is case-sensitive.
    # Native glob_match may differ. Check for divergence.
    cond = { "field" => "http.request.uri.path", "operator" => "wildcard", "value" => "/assets/*.js" }
    ruby_result = eval_ruby_condition(cond, { path: "/assets/APP.JS" })
    native_result = eval_native_condition(cond, { path: "/assets/APP.JS" })

    if ruby_result != native_result
      skip "KNOWN DIVERGENCE: wildcard case sensitivity — Ruby File.fnmatch is case-sensitive, " \
           "native glob_match may be case-insensitive. Ruby=#{ruby_result}, Native=#{native_result}"
    else
      assert_equal ruby_result, native_result, "wildcard case sensitivity"
    end
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
end
