# frozen_string_literal: true

require "minitest/autorun"
require "rack_attack_native"
require "openssl"
require "json"

class RuleSetSpec < Minitest::Test
  RULES_JSON = <<~JSON
    {
      "rules": [
        {
          "name": "health-check",
          "type": "safelist",
          "condition": {
            "or": [
              { "field": "http.request.uri.path", "operator": "eq", "value": "/healthz" },
              { "field": "http.request.uri.path", "operator": "eq", "value": "/readiness" }
            ]
          }
        },
        {
          "name": "internal-network",
          "type": "safelist",
          "condition": {
            "field": "ip.src", "operator": "in_ip_range",
            "value": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
          }
        },
        {
          "name": "bad-ips",
          "type": "blocklist",
          "condition": {
            "field": "ip.src", "operator": "in",
            "value": ["203.0.113.50", "198.51.100.99"]
          }
        },
        {
          "name": "bad-bots",
          "type": "blocklist",
          "condition": {
            "field": "http.user_agent", "operator": "matches",
            "value": "\\\\b(AhrefsBot|SemrushBot)\\\\b"
          }
        },
        {
          "name": "sensitive-paths",
          "type": "blocklist",
          "condition": {
            "and": [
              { "field": "http.request.uri.path", "operator": "matches", "value": "^/(admin|internal)" },
              { "not": { "field": "ip.src", "operator": "in_ip_range", "value": ["10.0.0.0/8"] } }
            ]
          }
        },
        {
          "name": "api-rate",
          "type": "throttle",
          "limit": 100,
          "period": 60,
          "key": ["ip.src"],
          "condition": {
            "field": "http.request.uri.path", "operator": "starts_with", "value": "/api/"
          }
        },
        {
          "name": "api-version",
          "type": "track",
          "condition": {
            "field": "http.request.uri.path", "operator": "matches",
            "value": "^/api/v[0-9]+/"
          }
        },
        {
          "name": "admin-access",
          "type": "track",
          "condition": {
            "field": "http.request.uri.path", "operator": "starts_with", "value": "/admin"
          }
        }
      ]
    }
  JSON

  def setup
    @rs = RackAttackNative::RuleSet.from_json(RULES_JSON)
  end

  def make_request(overrides = {})
    {
      path: "/",
      method: "GET",
      ip: "203.0.113.1",
      user_agent: "Mozilla/5.0",
      query_string: "",
      content_length: 0,
      headers: {},
      cookies: {}
    }.merge(overrides)
  end

  def test_rule_count
    assert_equal 8, @rs.rule_count
  end

  def test_safelist_health_check
    result = @rs.evaluate(make_request(path: "/healthz"))
    assert_equal "health-check", result[:safelisted]
    assert_nil result[:blocklisted]
  end

  def test_safelist_internal_ip
    result = @rs.evaluate(make_request(path: "/api/v2/users", ip: "10.0.1.50"))
    assert_equal "internal-network", result[:safelisted]
  end

  def test_safelist_short_circuits
    # Internal IP accessing /admin should be safelisted, not tracked
    result = @rs.evaluate(make_request(path: "/admin", ip: "10.0.1.50"))
    assert_equal "internal-network", result[:safelisted]
    assert_empty result[:tracked]
  end

  def test_blocklist_bad_ip
    result = @rs.evaluate(make_request(ip: "203.0.113.50"))
    assert_nil result[:safelisted]
    assert_equal "bad-ips", result[:blocklisted]
  end

  def test_blocklist_bad_bot
    result = @rs.evaluate(make_request(user_agent: "Mozilla/5.0 (compatible; AhrefsBot/7.0)"))
    assert_equal "bad-bots", result[:blocklisted]
  end

  def test_blocklist_sensitive_path_external
    result = @rs.evaluate(make_request(path: "/admin/users"))
    assert_equal "sensitive-paths", result[:blocklisted]
  end

  def test_blocklist_sensitive_path_internal_allowed
    # Internal IP should be safelisted before blocklist is checked
    result = @rs.evaluate(make_request(path: "/admin/users", ip: "10.0.0.5"))
    assert_equal "internal-network", result[:safelisted]
    assert_nil result[:blocklisted]
  end

  def test_throttle_match
    result = @rs.evaluate(make_request(path: "/api/v2/users"))
    assert_nil result[:safelisted]
    assert_nil result[:blocklisted]
    assert_equal 1, result[:throttle_matches].length
    tm = result[:throttle_matches][0]
    assert_equal "api-rate", tm[:name]
    assert_equal "203.0.113.1", tm[:discriminator]
    assert_equal 100, tm[:limit]
    assert_equal 60, tm[:period]
  end

  def test_throttle_no_match_non_api
    result = @rs.evaluate(make_request(path: "/about"))
    assert_empty result[:throttle_matches]
  end

  def test_track_api_version
    result = @rs.evaluate(make_request(path: "/api/v2/users"))
    assert_includes result[:tracked], "api-version"
  end

  def test_track_admin_access
    # External IP on /admin gets blocklisted, not tracked
    result = @rs.evaluate(make_request(path: "/admin/dashboard"))
    assert_equal "sensitive-paths", result[:blocklisted]
    assert_empty result[:tracked]
  end

  def test_no_match
    result = @rs.evaluate(make_request(path: "/about"))
    assert_nil result[:safelisted]
    assert_nil result[:blocklisted]
    assert_empty result[:throttle_matches]
    assert_empty result[:tracked]
  end

  def test_invalid_json_raises
    assert_raises(ArgumentError) { RackAttackNative::RuleSet.from_json("not json") }
  end

  def test_invalid_field_raises
    bad_json = '{"rules": [{"name": "x", "type": "safelist", "condition": {"field": "bad.field", "operator": "eq", "value": "x"}}]}'
    assert_raises(ArgumentError) { RackAttackNative::RuleSet.from_json(bad_json) }
  end

  def test_invalid_operator_raises
    bad_json = '{"rules": [{"name": "x", "type": "safelist", "condition": {"field": "ip.src", "operator": "bad_op", "value": "x"}}]}'
    assert_raises(ArgumentError) { RackAttackNative::RuleSet.from_json(bad_json) }
  end

  def test_header_field
    json = '{"rules": [{"name": "key-check", "type": "safelist", "condition": {"field": "http.request.headers[\\"x-api-key\\"]", "operator": "eq", "value": "secret"}}]}'
    rs = RackAttackNative::RuleSet.from_json(json)
    result = rs.evaluate(make_request(headers: { "x-api-key" => "secret" }))
    assert_equal "key-check", result[:safelisted]
  end

  def test_cookie_field
    json = '{"rules": [{"name": "session-check", "type": "track", "condition": {"field": "http.request.cookies[\\"_session_id\\"]", "operator": "exists"}}]}'
    rs = RackAttackNative::RuleSet.from_json(json)
    result = rs.evaluate(make_request(cookies: { "_session_id" => "abc123" }))
    assert_includes result[:tracked], "session-check"
  end

  def test_content_length_gt
    json = '{"rules": [{"name": "big-body", "type": "blocklist", "condition": {"field": "http.request.body.size", "operator": "gt", "value": 10485760}}]}'
    rs = RackAttackNative::RuleSet.from_json(json)
    result = rs.evaluate(make_request(content_length: 20_000_000))
    assert_equal "big-body", result[:blocklisted]
  end

  def test_contains_operator
    json = '{"rules": [{"name": "traversal", "type": "blocklist", "condition": {"field": "http.request.uri.path", "operator": "contains", "value": ".."}}]}'
    rs = RackAttackNative::RuleSet.from_json(json)
    result = rs.evaluate(make_request(path: "/../../etc/passwd"))
    assert_equal "traversal", result[:blocklisted]
  end

  def test_ends_with_operator
    json = '{"rules": [{"name": "js-files", "type": "track", "condition": {"field": "http.request.uri.path", "operator": "ends_with", "value": ".js"}}]}'
    rs = RackAttackNative::RuleSet.from_json(json)
    result = rs.evaluate(make_request(path: "/assets/app.js"))
    assert_includes result[:tracked], "js-files"
  end

  def test_not_in_operator
    json = '{"rules": [{"name": "non-standard", "type": "track", "condition": {"field": "http.request.method", "operator": "not_in", "value": ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]}}]}'
    rs = RackAttackNative::RuleSet.from_json(json)
    result = rs.evaluate(make_request(method: "TRACE"))
    assert_includes result[:tracked], "non-standard"
  end

  def test_not_in_ip_range
    json = '{"rules": [{"name": "external", "type": "track", "condition": {"field": "ip.src", "operator": "not_in_ip_range", "value": ["10.0.0.0/8"]}}]}'
    rs = RackAttackNative::RuleSet.from_json(json)
    result = rs.evaluate(make_request(ip: "203.0.113.1"))
    assert_includes result[:tracked], "external"
  end

  # ---------------------------------------------------------------------------
  # JWT support tests
  # ---------------------------------------------------------------------------

  HMAC_SECRET = "test-secret-key-for-hmac-256"

  def self.base64url_encode(data)
    [data].pack("m0").tr("+/", "-_").tr("=", "")
  end

  def self.hmac_jwt(payload, secret = HMAC_SECRET)
    header = base64url_encode('{"alg":"HS256","typ":"JWT"}')
    payload_b64 = base64url_encode(JSON.generate(payload))
    signing_input = "#{header}.#{payload_b64}"
    signature = base64url_encode(
      OpenSSL::HMAC.digest("SHA256", secret, signing_input)
    )
    "#{signing_input}.#{signature}"
  end

  VALID_HS256_JWT = hmac_jwt(
    "sub" => "user_12345",
    "iss" => "auth.example.com",
    "aud" => "api.example.com",
    "exp" => Time.now.to_i + 3600,
    "roles" => ["admin", "user"],
    "active" => true,
    "count" => 42
  )

  WRONG_SECRET_JWT = hmac_jwt(
    { "sub" => "user_99999", "iss" => "evil.example.com" },
    "wrong-secret"
  )

  JWT_RULES_JSON = <<~JSON
    {
      "jwt_keys": [
        { "algorithm": "HS256", "key": "#{HMAC_SECRET}" }
      ],
      "rules": [
        {
          "name": "jwt-sub-throttle",
          "type": "throttle",
          "limit": 100,
          "period": 60,
          "key": ["jwt.payload[\\"sub\\"]"],
          "condition": {
            "and": [
              { "field": "http.request.uri.path", "operator": "starts_with", "value": "/api/" },
              { "field": "jwt.payload[\\"sub\\"]", "operator": "exists" }
            ]
          }
        },
        {
          "name": "jwt-alg-track",
          "type": "track",
          "condition": {
            "field": "jwt.header[\\"alg\\"]", "operator": "eq", "value": "HS256"
          }
        },
        {
          "name": "jwt-iss-check",
          "type": "track",
          "condition": {
            "field": "jwt.payload[\\"iss\\"]", "operator": "eq", "value": "auth.example.com"
          }
        },
        {
          "name": "jwt-valid-track",
          "type": "track",
          "condition": {
            "field": "jwt.valid", "operator": "exists"
          }
        },
        {
          "name": "jwt-invalid-block",
          "type": "blocklist",
          "condition": {
            "and": [
              { "field": "jwt.payload[\\"sub\\"]", "operator": "exists" },
              { "field": "jwt.valid", "operator": "not_exists" }
            ]
          }
        },
        {
          "name": "jwt-verified-sub-track",
          "type": "track",
          "condition": {
            "field": "jwt.verified_payload[\\"sub\\"]", "operator": "eq", "value": "user_12345"
          }
        }
      ]
    }
  JSON

  def setup_jwt
    @jwt_rs = RackAttackNative::RuleSet.from_json(JWT_RULES_JSON)
  end

  def make_jwt_request(token, overrides = {})
    make_request({
      path: "/api/v2/orders",
      authorization: "Bearer #{token}"
    }.merge(overrides))
  end

  def test_jwt_rule_count
    setup_jwt
    assert_equal 6, @jwt_rs.rule_count
  end

  def test_jwt_unverified_payload_throttle
    setup_jwt
    result = @jwt_rs.evaluate(make_jwt_request(VALID_HS256_JWT))
    assert_equal 1, result[:throttle_matches].length
    tm = result[:throttle_matches][0]
    assert_equal "jwt-sub-throttle", tm[:name]
    assert_equal "user_12345", tm[:discriminator]
  end

  def test_jwt_header_field
    setup_jwt
    result = @jwt_rs.evaluate(make_jwt_request(VALID_HS256_JWT))
    assert_includes result[:tracked], "jwt-alg-track"
  end

  def test_jwt_unverified_payload_issuer
    setup_jwt
    result = @jwt_rs.evaluate(make_jwt_request(VALID_HS256_JWT))
    assert_includes result[:tracked], "jwt-iss-check"
  end

  def test_jwt_valid_with_correct_key
    setup_jwt
    result = @jwt_rs.evaluate(make_jwt_request(VALID_HS256_JWT))
    assert_includes result[:tracked], "jwt-valid-track"
    assert_nil result[:blocklisted]
  end

  def test_jwt_invalid_with_wrong_key
    setup_jwt
    result = @jwt_rs.evaluate(make_jwt_request(WRONG_SECRET_JWT))
    assert_equal "jwt-invalid-block", result[:blocklisted]
  end

  def test_jwt_verified_payload_claim
    setup_jwt
    result = @jwt_rs.evaluate(make_jwt_request(VALID_HS256_JWT))
    assert_includes result[:tracked], "jwt-verified-sub-track"
  end

  def test_jwt_verified_payload_fails_with_wrong_key
    setup_jwt
    # Wrong secret JWT: unverified payload exists but verified does not
    result = @jwt_rs.evaluate(make_jwt_request(WRONG_SECRET_JWT, path: "/other"))
    refute_includes result[:tracked], "jwt-verified-sub-track"
  end

  def test_jwt_no_token
    setup_jwt
    result = @jwt_rs.evaluate(make_request(path: "/api/v2/orders"))
    assert_empty result[:throttle_matches]
    refute_includes result[:tracked], "jwt-valid-track"
  end

  def test_jwt_no_keys_config
    # Rules with jwt fields but no jwt_keys configured
    json = '{"rules": [{"name": "jwt-track", "type": "track", "condition": {"field": "jwt.valid", "operator": "exists"}}]}'
    rs = RackAttackNative::RuleSet.from_json(json)
    result = rs.evaluate(make_jwt_request(VALID_HS256_JWT))
    refute_includes result[:tracked], "jwt-track"
  end

  def test_jwt_composite_throttle_key
    # Throttle key combining ip.src and jwt.payload["sub"]
    json = <<~JSON
      {
        "jwt_keys": [{ "algorithm": "HS256", "key": "#{HMAC_SECRET}" }],
        "rules": [{
          "name": "composite-key",
          "type": "throttle",
          "limit": 50, "period": 60,
          "key": ["ip.src", "jwt.payload[\\"sub\\"]"],
          "condition": { "field": "jwt.payload[\\"sub\\"]", "operator": "exists" }
        }]
      }
    JSON
    rs = RackAttackNative::RuleSet.from_json(json)
    result = rs.evaluate(make_jwt_request(VALID_HS256_JWT))
    assert_equal 1, result[:throttle_matches].length
    assert_equal "203.0.113.1:user_12345", result[:throttle_matches][0][:discriminator]
  end

  def test_jwt_malformed_token
    setup_jwt
    # Not 3 dot-separated parts
    result = @jwt_rs.evaluate(make_request(path: "/api/v2/orders", authorization: "Bearer not-a-jwt"))
    assert_empty result[:throttle_matches]
    refute_includes result[:tracked], "jwt-alg-track"
  end

  def test_jwt_non_bearer_auth_header
    setup_jwt
    # Basic auth header should not be treated as JWT
    result = @jwt_rs.evaluate(make_request(path: "/api/v2/orders", authorization: "Basic dXNlcjpwYXNz"))
    assert_empty result[:throttle_matches]
    refute_includes result[:tracked], "jwt-alg-track"
  end

  def test_jwt_array_claim_serialization
    # Array claims should serialize as JSON strings
    json = <<~JSON
      {
        "jwt_keys": [{ "algorithm": "HS256", "key": "#{HMAC_SECRET}" }],
        "rules": [{
          "name": "roles-track",
          "type": "track",
          "condition": { "field": "jwt.payload[\\"roles\\"]", "operator": "contains", "value": "admin" }
        }]
      }
    JSON
    rs = RackAttackNative::RuleSet.from_json(json)
    result = rs.evaluate(make_jwt_request(VALID_HS256_JWT))
    assert_includes result[:tracked], "roles-track"
  end

  # ---------------------------------------------------------------------------
  # Transform tests
  # ---------------------------------------------------------------------------

  def test_transform_lower
    json = '{"rules": [{"name": "bot-check", "type": "blocklist", "condition": {"field": "http.user_agent", "operator": "contains", "value": "bot", "transform": "lower"}}]}'
    rs = RackAttackNative::RuleSet.from_json(json)
    result = rs.evaluate(make_request(user_agent: "AhrefsBot/7.0"))
    assert_equal "bot-check", result[:blocklisted]
  end

  def test_transform_url_decode
    json = '{"rules": [{"name": "traversal", "type": "blocklist", "condition": {"field": "http.request.uri.path", "operator": "contains", "value": "..", "transform": "url_decode"}}]}'
    rs = RackAttackNative::RuleSet.from_json(json)
    result = rs.evaluate(make_request(path: "/foo/%2e%2e/bar"))
    assert_equal "traversal", result[:blocklisted]
  end

  def test_transform_chained
    json = '{"rules": [{"name": "sqli", "type": "blocklist", "condition": {"field": "http.request.uri.query", "operator": "contains", "value": "union select", "transform": ["url_decode", "lower"]}}]}'
    rs = RackAttackNative::RuleSet.from_json(json)
    result = rs.evaluate(make_request(query_string: "q=UNION%20SELECT%20*"))
    assert_equal "sqli", result[:blocklisted]
  end

  def test_transform_length
    json = '{"rules": [{"name": "long-path", "type": "track", "condition": {"field": "http.request.uri.path", "operator": "gt", "value": 10, "transform": "length"}}]}'
    rs = RackAttackNative::RuleSet.from_json(json)
    result = rs.evaluate(make_request(path: "/api/v2/users/42"))
    assert_includes result[:tracked], "long-path"
  end

  # ---------------------------------------------------------------------------
  # Wildcard operator tests
  # ---------------------------------------------------------------------------

  def test_wildcard_operator
    json = '{"rules": [{"name": "api-wildcard", "type": "track", "condition": {"field": "http.request.uri.path", "operator": "wildcard", "value": "/api/*/users"}}]}'
    rs = RackAttackNative::RuleSet.from_json(json)
    result = rs.evaluate(make_request(path: "/api/v2/users"))
    assert_includes result[:tracked], "api-wildcard"
  end

  def test_wildcard_no_match
    json = '{"rules": [{"name": "api-wildcard", "type": "track", "condition": {"field": "http.request.uri.path", "operator": "wildcard", "value": "/admin/*"}}]}'
    rs = RackAttackNative::RuleSet.from_json(json)
    result = rs.evaluate(make_request(path: "/api/v2/users"))
    assert_empty result[:tracked]
  end

  def test_wildcard_case_insensitive
    json = '{"rules": [{"name": "ext-wildcard", "type": "track", "condition": {"field": "http.request.uri.path", "operator": "wildcard", "value": "/assets/*.js"}}]}'
    rs = RackAttackNative::RuleSet.from_json(json)
    result = rs.evaluate(make_request(path: "/assets/APP.JS"))
    assert_includes result[:tracked], "ext-wildcard"
  end

  # ---------------------------------------------------------------------------
  # New field tests
  # ---------------------------------------------------------------------------

  def test_uri_field_with_query
    json = '{"rules": [{"name": "uri-track", "type": "track", "condition": {"field": "http.request.uri", "operator": "contains", "value": "?page="}}]}'
    rs = RackAttackNative::RuleSet.from_json(json)
    result = rs.evaluate(make_request(path: "/api/users", query_string: "page=1"))
    assert_includes result[:tracked], "uri-track"
  end

  def test_path_extension_field
    json = '{"rules": [{"name": "js-files", "type": "safelist", "condition": {"and": [{"field": "http.request.method", "operator": "eq", "value": "GET"}, {"field": "http.request.uri.path.extension", "operator": "in", "value": ["js", "css", "png"]}]}}]}'
    rs = RackAttackNative::RuleSet.from_json(json)
    result = rs.evaluate(make_request(path: "/assets/app.js"))
    assert_equal "js-files", result[:safelisted]
  end

  def test_path_extension_no_ext
    json = '{"rules": [{"name": "ext-check", "type": "track", "condition": {"field": "http.request.uri.path.extension", "operator": "exists"}}]}'
    rs = RackAttackNative::RuleSet.from_json(json)
    result = rs.evaluate(make_request(path: "/api/users"))
    assert_empty result[:tracked]
  end

  def test_query_param_field
    json = '{"rules": [{"name": "search-q", "type": "track", "condition": {"field": "http.request.uri.args[\\"q\\"]", "operator": "exists"}}]}'
    rs = RackAttackNative::RuleSet.from_json(json)
    result = rs.evaluate(make_request(query_string: "q=hello&page=1"))
    assert_includes result[:tracked], "search-q"
  end

  def test_query_param_missing
    json = '{"rules": [{"name": "search-q", "type": "track", "condition": {"field": "http.request.uri.args[\\"q\\"]", "operator": "exists"}}]}'
    rs = RackAttackNative::RuleSet.from_json(json)
    result = rs.evaluate(make_request(query_string: "page=1"))
    assert_empty result[:tracked]
  end

  def test_body_raw_field
    json = '{"rules": [{"name": "body-check", "type": "track", "condition": {"field": "http.request.body.raw", "operator": "contains", "value": "password"}}]}'
    rs = RackAttackNative::RuleSet.from_json(json)
    result = rs.evaluate(make_request(body: "email=user@example.com&password=secret"))
    assert_includes result[:tracked], "body-check"
  end

  def test_body_json_field
    json = '{"rules": [{"name": "action-check", "type": "track", "condition": {"field": "http.request.body.json[\\"action\\"]", "operator": "eq", "value": "delete"}}]}'
    rs = RackAttackNative::RuleSet.from_json(json)
    result = rs.evaluate(make_request(body: '{"action": "delete", "id": 42}'))
    assert_includes result[:tracked], "action-check"
  end

  def test_body_json_field_no_body
    json = '{"rules": [{"name": "action-check", "type": "track", "condition": {"field": "http.request.body.json[\\"action\\"]", "operator": "exists"}}]}'
    rs = RackAttackNative::RuleSet.from_json(json)
    result = rs.evaluate(make_request)
    assert_empty result[:tracked]
  end

  # ===========================================================================
  # Stress & Robustness Tests
  # ===========================================================================

  # ---------------------------------------------------------------------------
  # Concurrent evaluate (thread safety / GVL release)
  # ---------------------------------------------------------------------------

  [4, 8, 16, 32].each do |n_threads|
    define_method(:"test_concurrent_evaluate_#{n_threads}_threads") do
      iterations_per_thread = 500
      errors = Queue.new

      threads = (0...n_threads).map do |t|
        Thread.new do
          iterations_per_thread.times do |i|
            # Alternate between different request shapes to stress different code paths
            case i % 4
            when 0
              result = @rs.evaluate(make_request(path: "/healthz"))
              unless result[:safelisted] == "health-check"
                errors << "Thread #{t}, iter #{i}: expected safelisted=health-check, got #{result[:safelisted].inspect}"
              end
            when 1
              result = @rs.evaluate(make_request(ip: "203.0.113.50"))
              unless result[:blocklisted] == "bad-ips"
                errors << "Thread #{t}, iter #{i}: expected blocklisted=bad-ips, got #{result[:blocklisted].inspect}"
              end
            when 2
              result = @rs.evaluate(make_request(path: "/api/v2/users"))
              unless result[:throttle_matches].length == 1
                errors << "Thread #{t}, iter #{i}: expected 1 throttle match, got #{result[:throttle_matches].length}"
              end
            when 3
              result = @rs.evaluate(make_request(path: "/about", ip: "1.2.3.4"))
              unless result[:safelisted].nil? && result[:blocklisted].nil?
                errors << "Thread #{t}, iter #{i}: expected no match, got safelisted=#{result[:safelisted].inspect} blocklisted=#{result[:blocklisted].inspect}"
              end
            end
          end
        end
      end

      threads.each(&:join)
      collected_errors = []
      collected_errors << errors.pop until errors.empty?
      assert_empty collected_errors, "Concurrent evaluate errors:\n#{collected_errors.first(10).join("\n")}"
    end
  end

  # ---------------------------------------------------------------------------
  # Concurrent evaluate with JWT (exercises lazy JWT decode caches)
  # ---------------------------------------------------------------------------

  [4, 16].each do |n_threads|
    define_method(:"test_concurrent_jwt_evaluate_#{n_threads}_threads") do
      setup_jwt
      iterations_per_thread = 250
      errors = Queue.new

      threads = (0...n_threads).map do |t|
        Thread.new do
          iterations_per_thread.times do |i|
            if i.even?
              result = @jwt_rs.evaluate(make_jwt_request(VALID_HS256_JWT))
              unless result[:throttle_matches].length == 1 && result[:throttle_matches][0][:discriminator] == "user_12345"
                errors << "Thread #{t}, iter #{i}: valid JWT got unexpected result"
              end
            else
              result = @jwt_rs.evaluate(make_jwt_request(WRONG_SECRET_JWT))
              unless result[:blocklisted] == "jwt-invalid-block"
                errors << "Thread #{t}, iter #{i}: wrong-key JWT expected blocklist, got #{result[:blocklisted].inspect}"
              end
            end
          end
        end
      end

      threads.each(&:join)
      collected_errors = []
      collected_errors << errors.pop until errors.empty?
      assert_empty collected_errors, "Concurrent JWT evaluate errors:\n#{collected_errors.first(10).join("\n")}"
    end
  end

  # ---------------------------------------------------------------------------
  # Large rule set (1000+ rules)
  # ---------------------------------------------------------------------------

  def test_large_rule_set_1000_rules
    rules = (0...1000).map do |i|
      {
        name: "rule-#{i}",
        type: %w[safelist blocklist throttle track][i % 4],
        limit: (i % 4 == 2 ? 100 : nil),
        period: (i % 4 == 2 ? 60 : nil),
        key: (i % 4 == 2 ? ["ip.src"] : nil),
        condition: {
          field: "http.request.uri.path",
          operator: "eq",
          value: "/path-#{i}"
        }
      }.compact
    end

    json = JSON.generate({ rules: rules })
    rs = RackAttackNative::RuleSet.from_json(json)
    assert_equal 1000, rs.rule_count

    # Match a rule deep in the list (rule-997 is a track since 997 % 4 == 1 → blocklist)
    # rule-999: 999 % 4 == 3 → track
    result = rs.evaluate(make_request(path: "/path-999"))
    assert_includes result[:tracked], "rule-999"

    # No match
    result = rs.evaluate(make_request(path: "/nonexistent"))
    assert_nil result[:safelisted]
    assert_nil result[:blocklisted]
    assert_empty result[:throttle_matches]
    assert_empty result[:tracked]
  end

  # ---------------------------------------------------------------------------
  # Very long strings in request fields
  # ---------------------------------------------------------------------------

  def test_very_long_path_1mb
    long_path = "/" + "a" * (1024 * 1024)
    result = @rs.evaluate(make_request(path: long_path))
    # Should not crash, just no match
    assert_nil result[:safelisted]
    assert_nil result[:blocklisted]
  end

  def test_very_long_user_agent_1mb
    long_ua = "Mozilla/5.0 " + "x" * (1024 * 1024)
    result = @rs.evaluate(make_request(user_agent: long_ua))
    assert_nil result[:safelisted]
    assert_nil result[:blocklisted]
  end

  def test_very_long_query_string_1mb
    long_qs = "q=" + "a" * (1024 * 1024)
    result = @rs.evaluate(make_request(query_string: long_qs))
    assert_nil result[:safelisted]
  end

  def test_very_long_body_1mb
    long_body = "x" * (1024 * 1024)
    result = @rs.evaluate(make_request(body: long_body))
    assert_nil result[:safelisted]
  end

  def test_very_long_header_value
    json = '{"rules": [{"name": "key-check", "type": "safelist", "condition": {"field": "http.request.headers[\\"x-api-key\\"]", "operator": "eq", "value": "secret"}}]}'
    rs = RackAttackNative::RuleSet.from_json(json)
    result = rs.evaluate(make_request(headers: { "x-api-key" => "a" * (1024 * 1024) }))
    assert_nil result[:safelisted]
  end

  def test_very_long_cookie_value
    json = '{"rules": [{"name": "sess", "type": "track", "condition": {"field": "http.request.cookies[\\"sid\\"]", "operator": "exists"}}]}'
    rs = RackAttackNative::RuleSet.from_json(json)
    result = rs.evaluate(make_request(cookies: { "sid" => "v" * (1024 * 1024) }))
    assert_includes result[:tracked], "sess"
  end

  # ---------------------------------------------------------------------------
  # Very long strings in rule config (JSON payload)
  # ---------------------------------------------------------------------------

  def test_enormous_json_config
    # Rule with a very long regex pattern
    long_pattern = "(a|b|c|d|e|f){100}" + "|xxx" * 10_000
    json = JSON.generate({
      rules: [{
        name: "big-regex",
        type: "track",
        condition: {
          field: "http.request.uri.path",
          operator: "matches",
          value: long_pattern
        }
      }]
    })

    rs = RackAttackNative::RuleSet.from_json(json)
    result = rs.evaluate(make_request(path: "/xxx"))
    assert_includes result[:tracked], "big-regex"
  end

  def test_config_with_many_ip_ranges
    ranges = (0...256).map { |i| "#{i}.0.0.0/8" }
    json = JSON.generate({
      rules: [{
        name: "all-ips",
        type: "safelist",
        condition: {
          field: "ip.src",
          operator: "in_ip_range",
          value: ranges
        }
      }]
    })

    rs = RackAttackNative::RuleSet.from_json(json)
    result = rs.evaluate(make_request(ip: "42.1.2.3"))
    assert_equal "all-ips", result[:safelisted]
  end

  def test_config_with_large_in_set
    # 10,000 IPs in an "in" set
    ips = (0...10_000).map { |i| "10.#{i / 256}.#{i % 256}.1" }
    json = JSON.generate({
      rules: [{
        name: "big-set",
        type: "blocklist",
        condition: {
          field: "ip.src",
          operator: "in",
          value: ips
        }
      }]
    })

    rs = RackAttackNative::RuleSet.from_json(json)
    # Match one in the middle
    result = rs.evaluate(make_request(ip: "10.19.136.1"))
    assert_equal "big-set", result[:blocklisted]

    # No match
    result = rs.evaluate(make_request(ip: "192.168.1.1"))
    assert_nil result[:blocklisted]
  end

  # ---------------------------------------------------------------------------
  # Missing / nil / empty fields in request hash
  # ---------------------------------------------------------------------------

  def test_completely_empty_request_hash
    result = @rs.evaluate({})
    # All serde defaults kick in — should not crash
    assert_nil result[:safelisted]
    assert_nil result[:blocklisted]
  end

  def test_request_with_only_path
    result = @rs.evaluate({ path: "/healthz" })
    assert_equal "health-check", result[:safelisted]
  end

  def test_nil_user_agent
    result = @rs.evaluate(make_request(user_agent: nil))
    assert_nil result[:safelisted]
  end

  def test_empty_string_fields
    result = @rs.evaluate(make_request(path: "", ip: "", user_agent: "", query_string: ""))
    assert_nil result[:safelisted]
    assert_nil result[:blocklisted]
  end

  def test_nil_body
    result = @rs.evaluate(make_request(body: nil))
    assert_nil result[:safelisted]
  end

  def test_empty_headers_and_cookies
    result = @rs.evaluate(make_request(headers: {}, cookies: {}))
    assert_nil result[:safelisted]
  end

  # ---------------------------------------------------------------------------
  # Wrong types in request hash (should raise ArgumentError from serde)
  # ---------------------------------------------------------------------------

  def test_wrong_type_path_integer
    assert_raises(ArgumentError) { @rs.evaluate({ path: 12345 }) }
  end

  def test_wrong_type_ip_array
    assert_raises(ArgumentError) { @rs.evaluate({ ip: ["1.2.3.4"] }) }
  end

  def test_wrong_type_headers_string
    assert_raises(ArgumentError) { @rs.evaluate({ headers: "not-a-hash" }) }
  end

  def test_wrong_type_cookies_array
    assert_raises(ArgumentError) { @rs.evaluate({ cookies: [1, 2, 3] }) }
  end

  def test_wrong_type_content_length_string
    # serde may or may not accept "123" as u64; this should at least not crash
    assert_raises(ArgumentError) { @rs.evaluate({ content_length: "not_a_number" }) }
  end

  # ---------------------------------------------------------------------------
  # Invalid from_json inputs
  # ---------------------------------------------------------------------------

  def test_empty_string_json
    assert_raises(ArgumentError) { RackAttackNative::RuleSet.from_json("") }
  end

  def test_null_json
    assert_raises(ArgumentError) { RackAttackNative::RuleSet.from_json("null") }
  end

  def test_json_array_instead_of_object
    assert_raises(ArgumentError) { RackAttackNative::RuleSet.from_json("[1,2,3]") }
  end

  def test_json_with_unknown_rule_type
    json = '{"rules": [{"name": "x", "type": "unknown_type", "condition": {"field": "ip.src", "operator": "eq", "value": "1.2.3.4"}}]}'
    assert_raises(ArgumentError) { RackAttackNative::RuleSet.from_json(json) }
  end

  def test_deeply_nested_conditions
    # 50 levels of nested AND conditions
    condition = { field: "http.request.uri.path", operator: "eq", value: "/deep" }
    50.times { condition = { "and" => [condition] } }
    json = JSON.generate({ rules: [{ name: "deep", type: "track", condition: condition }] }, max_nesting: 200)
    rs = RackAttackNative::RuleSet.from_json(json)
    result = rs.evaluate(make_request(path: "/deep"))
    assert_includes result[:tracked], "deep"
  end

  # ---------------------------------------------------------------------------
  # Rapid repeated evaluate (memory / state correctness)
  # ---------------------------------------------------------------------------

  def test_rapid_repeated_evaluate_100k
    req = make_request(path: "/api/v2/users")
    100_000.times { @rs.evaluate(req) }
    # Final call should still be correct
    result = @rs.evaluate(req)
    assert_equal 1, result[:throttle_matches].length
    assert_equal "api-rate", result[:throttle_matches][0][:name]
  end

  # ---------------------------------------------------------------------------
  # Special / adversarial string content
  # ---------------------------------------------------------------------------

  def test_null_bytes_in_path
    result = @rs.evaluate(make_request(path: "/api/v2/\x00users"))
    assert_nil result[:safelisted]
  end

  def test_unicode_in_path
    result = @rs.evaluate(make_request(path: "/api/v2/用户/42"))
    assert_nil result[:safelisted]
  end

  def test_unicode_in_user_agent
    result = @rs.evaluate(make_request(user_agent: "Mözillä/5.0 (Ünïcödé; Tëst) 🤖"))
    assert_nil result[:blocklisted]
  end

  def test_newlines_and_control_chars_in_fields
    result = @rs.evaluate(make_request(
      path: "/api/v2/users\r\n",
      user_agent: "Mozilla\t5.0\n",
      query_string: "q=hello\x00world"
    ))
    assert_nil result[:safelisted]
  end

  def test_jwt_with_large_payload
    setup_jwt
    # JWT with a large claim value (10KB — exercises base64 decode on bigger tokens)
    # Include "exp" so the token passes signature+expiry validation (jwt.valid exists),
    # otherwise jwt-invalid-block fires and the request gets blocklisted.
    large_claim = "x" * (10 * 1024)
    large_jwt = self.class.hmac_jwt({ "sub" => "user_1", "exp" => Time.now.to_i + 3600, "data" => large_claim })
    result = @jwt_rs.evaluate(make_jwt_request(large_jwt))
    assert_equal 1, result[:throttle_matches].length
    assert_equal "user_1", result[:throttle_matches][0][:discriminator]
  end

  def test_jwt_with_garbage_token
    setup_jwt
    result = @jwt_rs.evaluate(make_request(
      path: "/api/v2/orders",
      authorization: "Bearer " + "A" * 10_000
    ))
    # Should not crash — garbage token just won't match JWT rules
    assert_empty result[:throttle_matches]
  end

  def test_many_headers
    headers = {}
    1000.times { |i| headers["x-custom-#{i}"] = "value-#{i}" }
    result = @rs.evaluate(make_request(headers: headers))
    assert_nil result[:safelisted]
  end

  def test_many_cookies
    cookies = {}
    1000.times { |i| cookies["cookie_#{i}"] = "val_#{i}" }
    result = @rs.evaluate(make_request(cookies: cookies))
    assert_nil result[:safelisted]
  end
end
