#!/usr/bin/env ruby
# frozen_string_literal: true

#
# Rack::Attack Native Engine Benchmark
#
# Side-by-side comparison of Ruby block rules vs native Rust rule engine.
#
# Usage:
#   cd rack-attack-native && bundle exec rake compile && cd ..
#   ruby benchmark/benchmark_native.rb
#
# Dependencies:
#   gem install benchmark-ips jwt
#   The rack-attack-native gem must be compiled first.
#

$LOAD_PATH.unshift File.expand_path("../lib", __dir__)
$LOAD_PATH.unshift File.expand_path("../rack-attack-native/lib", __dir__)

require "rack"
require "rack/attack"
require "rack/attack/version"
require "benchmark/ips"
require "jwt"
require "json"
require "openssl"
require "ipaddr"
require "stringio"
require "rack_attack_native"

# ---------------------------------------------------------------------------
# Minimal in-memory cache store (avoids Redis/Memcached dependency)
# ---------------------------------------------------------------------------
class MemoryStore
  def initialize
    @data = {}
    @mutex = Mutex.new
  end

  def read(key)
    @mutex.synchronize { @data[key]&.fetch(:value) }
  end

  def write(key, value, options = {})
    @mutex.synchronize { @data[key] = { value: value } }
  end

  def increment(key, amount = 1, options = {})
    @mutex.synchronize do
      entry = @data[key]
      if entry
        entry[:value] += amount
        entry[:value]
      end
    end
  end

  def delete(key)
    @mutex.synchronize { @data.delete(key) }
  end

  def delete_matched(pattern)
    @mutex.synchronize do
      @data.delete_if { |k, _| k.match?(pattern) }
    end
  end
end

# ---------------------------------------------------------------------------
# RSA key pair for JWT benchmarks (Ruby-only rules)
# ---------------------------------------------------------------------------
RSA_PRIVATE = OpenSSL::PKey::RSA.generate(2048)
RSA_PUBLIC  = RSA_PRIVATE.public_key

VALID_JWT = JWT.encode(
  { "sub" => "user_12345", "iss" => "auth.example.com", "aud" => "api.example.com",
    "exp" => Time.now.to_i + 3600, "iat" => Time.now.to_i, "roles" => ["admin", "user"] },
  RSA_PRIVATE,
  "RS256"
)

EXPIRED_JWT = JWT.encode(
  { "sub" => "user_99999", "iss" => "auth.example.com", "aud" => "api.example.com",
    "exp" => Time.now.to_i - 3600, "iat" => Time.now.to_i - 7200 },
  RSA_PRIVATE,
  "RS256"
)

# ---------------------------------------------------------------------------
# Simulated data
# ---------------------------------------------------------------------------
BLOCKED_IPS = %w[
  203.0.113.50 198.51.100.99 192.0.2.42 10.99.99.1 172.16.255.1
  203.0.113.51 198.51.100.100 192.0.2.43 10.99.99.2 172.16.255.2
].freeze

BLOCKED_CIDRS = %w[
  198.18.0.0/15 100.64.0.0/10 192.88.99.0/24
].map { |cidr| IPAddr.new(cidr) }.freeze

INTERNAL_CIDRS = %w[
  10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 127.0.0.0/8
].map { |cidr| IPAddr.new(cidr) }.freeze

BLOCKED_USER_AGENTS = %w[AhrefsBot SemrushBot MJ12bot DotBot BLEXBot].freeze
BLOCKED_UA_PATTERN = /\b(#{BLOCKED_USER_AGENTS.join("|")})\b/i
SENSITIVE_PATH_PATTERN = %r{\A/(admin|internal|debug|monitoring|actuator|\.env|\.git|wp-admin|phpMyAdmin)}i
API_VERSION_PATTERN = %r{\A/api/v[0-9]+/}
STATIC_ASSET_PATTERN = %r{\.(css|js|png|jpg|jpeg|gif|ico|svg|woff2?|ttf|eot|map)\z}i
VALID_SESSION_PATTERN = /\A[a-f0-9]{32,128}\z/

INNER_APP = ->(_env) { [200, { "content-type" => "text/plain" }, ["OK"]] }

# ---------------------------------------------------------------------------
# Helper to build a Rack env hash
# ---------------------------------------------------------------------------
def build_env(method: "GET", path: "/", ip: "203.0.113.1",
              user_agent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
              headers: {}, cookies: {}, query_string: "", body: nil)
  env = {
    "REQUEST_METHOD"  => method.to_s.upcase,
    "PATH_INFO"       => path,
    "QUERY_STRING"    => query_string,
    "REMOTE_ADDR"     => ip,
    "HTTP_USER_AGENT" => user_agent,
    "HTTP_HOST"       => "api.example.com",
    "SERVER_NAME"     => "api.example.com",
    "SERVER_PORT"     => "443",
    "rack.url_scheme" => "https",
    "rack.input"      => StringIO.new(body.to_s),
    "rack.errors"     => $stderr,
  }
  headers.each do |key, value|
    rack_key = "HTTP_#{key.to_s.upcase.tr('-', '_')}"
    env[rack_key] = value.to_s
  end
  unless cookies.empty?
    env["HTTP_COOKIE"] = cookies.map { |k, v| "#{k}=#{v}" }.join("; ")
  end
  env
end

# ---------------------------------------------------------------------------
# Helper to build a native request data hash from a Rack env
# ---------------------------------------------------------------------------
def env_to_native(env)
  headers = {}
  cookies = {}

  env.each do |key, value|
    next unless key.is_a?(String) && value.is_a?(String)

    if key.start_with?("HTTP_") && key != "HTTP_USER_AGENT" && key != "HTTP_HOST" && key != "HTTP_COOKIE"
      header_name = key[5..].downcase.tr("_", "-")
      headers[header_name] = value
    end
  end

  if env["HTTP_COOKIE"]
    env["HTTP_COOKIE"].split("; ").each do |pair|
      k, v = pair.split("=", 2)
      cookies[k] = v if k && v
    end
  end

  body_str = nil
  if env["rack.input"]
    body_str = env["rack.input"].read
    env["rack.input"].rewind
  end

  {
    path: env["PATH_INFO"] || "/",
    method: env["REQUEST_METHOD"] || "GET",
    ip: env["REMOTE_ADDR"] || "",
    user_agent: env["HTTP_USER_AGENT"],
    host: env["HTTP_HOST"],
    query_string: env["QUERY_STRING"] || "",
    content_length: env["CONTENT_LENGTH"].to_i,
    authorization: env["HTTP_AUTHORIZATION"],
    body: body_str,
    headers: headers,
    cookies: cookies,
  }
end

# ---------------------------------------------------------------------------
# Cookie parser
# ---------------------------------------------------------------------------
def parse_cookies(cookie_string)
  return {} unless cookie_string

  cookie_string.split("; ").each_with_object({}) do |pair, hash|
    key, value = pair.split("=", 2)
    hash[key] = value
  end
end

# ---------------------------------------------------------------------------
# Configure Ruby Rack::Attack rules (same as benchmark.rb, minus JWT/Fail2Ban)
# ---------------------------------------------------------------------------
def configure_ruby_rules!
  Rack::Attack.enabled = true
  Rack::Attack.clear_configuration
  Rack::Attack.cache.store = MemoryStore.new
  Rack::Attack.notifier = nil

  # SAFELISTS
  Rack::Attack.safelist("health-check-endpoints") do |req|
    req.path == "/healthz" || req.path == "/readiness" || req.path == "/livez"
  end

  Rack::Attack.safelist("internal-network") do |req|
    ip = req.ip
    ip && INTERNAL_CIDRS.any? { |cidr| cidr.include?(ip) }
  rescue IPAddr::InvalidAddressError
    false
  end

  Rack::Attack.safelist("static-assets") do |req|
    req.get? && req.path.match?(STATIC_ASSET_PATTERN)
  end

  Rack::Attack.safelist("trusted-api-key") do |req|
    req.env["HTTP_X_SERVICE_API_KEY"] == "trusted-internal-service-key-abc123"
  end

  Rack::Attack.safelist("load-balancer-probe") do |req|
    ua = req.user_agent
    ua && (ua.start_with?("ELB-HealthChecker") || ua.start_with?("kube-probe"))
  end

  # BLOCKLISTS
  Rack::Attack.blocklist("known-bad-ips") do |req|
    BLOCKED_IPS.include?(req.ip)
  end

  Rack::Attack.blocklist("known-bad-cidrs") do |req|
    ip = req.ip
    ip && BLOCKED_CIDRS.any? { |cidr| cidr.include?(ip) }
  rescue IPAddr::InvalidAddressError
    false
  end

  Rack::Attack.blocklist("blocked-user-agents") do |req|
    ua = req.user_agent
    ua && ua.match?(BLOCKED_UA_PATTERN)
  end

  Rack::Attack.blocklist("sensitive-paths") do |req|
    req.path.match?(SENSITIVE_PATH_PATTERN) &&
      !INTERNAL_CIDRS.any? { |cidr| cidr.include?(req.ip) rescue false }
  end

  Rack::Attack.blocklist("sql-injection-probes") do |req|
    qs = req.query_string
    qs && qs.match?(/(\bunion\b.*\bselect\b|\bor\b\s+1\s*=\s*1|\bdrop\b\s+\btable\b)/i)
  end

  Rack::Attack.blocklist("path-traversal") do |req|
    req.path.include?("..") || req.path.match?(%r{%2e%2e|%252e}i)
  end

  Rack::Attack.blocklist("missing-ua-on-api") do |req|
    req.path.start_with?("/api/") && (req.user_agent.nil? || req.user_agent.empty?)
  end

  Rack::Attack.blocklist("readonly-endpoint-writes") do |req|
    req.path.start_with?("/api/v1/public/") &&
      !%w[GET HEAD OPTIONS].include?(req.request_method)
  end

  Rack::Attack.blocklist("oversized-body") do |req|
    content_length = req.env["CONTENT_LENGTH"].to_i
    content_length > 10_485_760
  end

  # THROTTLES
  Rack::Attack.throttle("global/ip", limit: 300, period: 60) { |req| req.ip }

  Rack::Attack.throttle("api/ip", limit: 100, period: 60) do |req|
    req.ip if req.path.start_with?("/api/")
  end

  Rack::Attack.throttle("login/ip", limit: 5, period: 60) do |req|
    req.ip if req.post? && req.path == "/auth/login"
  end

  Rack::Attack.throttle("login/email", limit: 5, period: 300) do |req|
    if req.post? && req.path == "/auth/login"
      req.env["HTTP_X_LOGIN_EMAIL"]&.to_s&.downcase&.strip
    end
  end

  Rack::Attack.throttle("password-reset/ip", limit: 3, period: 1800) do |req|
    req.ip if req.post? && req.path == "/auth/password-reset"
  end

  Rack::Attack.throttle("registration/ip", limit: 3, period: 3600) do |req|
    req.ip if req.post? && req.path == "/auth/register"
  end

  Rack::Attack.throttle("search/ip", limit: 20, period: 60) do |req|
    req.ip if req.get? && req.path.match?(%r{\A/api/v[0-9]+/search\z})
  end

  Rack::Attack.throttle("upload/ip", limit: 10, period: 300) do |req|
    req.ip if req.post? && req.path.match?(%r{\A/api/v[0-9]+/uploads\z})
  end

  Rack::Attack.throttle("graphql/ip", limit: 60, period: 60) do |req|
    req.ip if req.post? && req.path == "/graphql"
  end

  Rack::Attack.throttle("webhooks/ip", limit: 30, period: 60) do |req|
    req.ip if req.post? && req.path.start_with?("/webhooks/")
  end

  (1..5).each do |level|
    Rack::Attack.throttle("auth-bruteforce/level-#{level}", limit: (6 * level), period: (30**level)) do |req|
      req.ip if req.post? && req.path == "/auth/login"
    end
  end

  Rack::Attack.throttle("session/writes", limit: 30, period: 60) do |req|
    if %w[POST PUT PATCH DELETE].include?(req.request_method)
      cookies = parse_cookies(req.env["HTTP_COOKIE"])
      session_id = cookies["_session_id"]
      session_id if session_id && session_id.match?(VALID_SESSION_PATTERN)
    end
  end

  Rack::Attack.throttle("api/key", limit: 1000, period: 3600) do |req|
    req.env["HTTP_X_API_KEY"] if req.path.start_with?("/api/")
  end

  Rack::Attack.throttle("origin/rate", limit: 100, period: 60) do |req|
    origin = req.env["HTTP_ORIGIN"]
    origin if origin && !origin.end_with?(".example.com")
  end

  # TRACKS
  Rack::Attack.track("api-version") { |req| req.path.match?(API_VERSION_PATTERN) }
  Rack::Attack.track("admin-access") { |req| req.path.start_with?("/admin") }

  Rack::Attack.track("deprecated-endpoints") do |req|
    req.path.start_with?("/api/v1/") && req.path.match?(%r{/api/v1/(legacy|old|deprecated)})
  end

  Rack::Attack.track("high-rate-monitor", limit: 500, period: 60) { |req| req.ip }

  Rack::Attack.track("unusual-methods") do |req|
    !%w[GET POST PUT PATCH DELETE HEAD OPTIONS].include?(req.request_method)
  end

  Rack::Attack.track("cookieless-api") do |req|
    req.path.start_with?("/api/") && (req.env["HTTP_COOKIE"].nil? || req.env["HTTP_COOKIE"].empty?)
  end

  suspicious_ranges = %w[45.0.0.0/8 46.0.0.0/8].map { |c| IPAddr.new(c) }
  Rack::Attack.track("geo-suspicious") do |req|
    ip = req.ip
    ip && suspicious_ranges.any? { |cidr| cidr.include?(ip) rescue false }
  end

  # JWT rules
  Rack::Attack.throttle("jwt-sub-throttle", limit: 100, period: 60) do |req|
    if req.path.start_with?("/api/")
      auth = req.env["HTTP_AUTHORIZATION"]
      if auth&.start_with?("Bearer ")
        token = auth[7..]
        begin
          payload = JWT.decode(token, nil, false).first
          payload["sub"]
        rescue JWT::DecodeError
          nil
        end
      end
    end
  end

  Rack::Attack.track("jwt-wrong-audience") do |req|
    auth = req.env["HTTP_AUTHORIZATION"]
    if auth&.start_with?("Bearer ")
      begin
        payload = JWT.decode(auth[7..], nil, false).first
        payload["aud"] && payload["aud"] != "api.example.com"
      rescue JWT::DecodeError
        false
      end
    end
  end

  Rack::Attack.blocklist("jwt-expired-block") do |req|
    auth = req.env["HTTP_AUTHORIZATION"]
    if auth&.start_with?("Bearer ")
      token = auth[7..]
      begin
        # Check if token has a sub (is a JWT we care about)
        payload = JWT.decode(token, nil, false).first
        if payload["sub"]
          # Try to verify — if it fails, block
          begin
            JWT.decode(token, RSA_PUBLIC, true, algorithm: "RS256")
            false
          rescue JWT::DecodeError
            true
          end
        end
      rescue JWT::DecodeError
        false
      end
    end
  end
end

# ---------------------------------------------------------------------------
# Build representative request scenarios
# ---------------------------------------------------------------------------
def build_scenarios
  {
    "Normal GET (external IP)" => build_env(
      path: "/api/v2/users/42",
      headers: { "X-Api-Key" => "key_abc123", "Origin" => "https://app.example.com" },
      cookies: { "_session_id" => "a1b2c3d4e5f6" * 4 }
    ),
    "Normal POST with JWT" => build_env(
      method: "POST",
      path: "/api/v2/orders",
      headers: {
        "Authorization" => "Bearer #{VALID_JWT}",
        "X-Api-Key" => "key_abc123",
        "Content-Type" => "application/json"
      },
      cookies: { "_session_id" => "deadbeef" * 8 },
      body: '{"item":"widget","qty":1}'
    ),
    "Login attempt (POST)" => build_env(
      method: "POST",
      path: "/auth/login",
      headers: { "X-Login-Email" => "user@example.com" },
      body: "email=user@example.com&password=secret"
    ),
    "Static asset (safelisted)" => build_env(
      path: "/assets/app-abc123.js"
    ),
    "Internal IP (safelisted)" => build_env(
      path: "/api/v1/internal/metrics",
      ip: "10.0.1.50"
    ),
    "Health check (safelisted)" => build_env(
      path: "/healthz",
      ip: "10.0.0.1",
      user_agent: "kube-probe/1.25"
    ),
    "Blocked IP" => build_env(
      path: "/api/v2/users",
      ip: "203.0.113.50"
    ),
    "Blocked User-Agent" => build_env(
      path: "/",
      user_agent: "Mozilla/5.0 (compatible; AhrefsBot/7.0)"
    ),
    "Sensitive path (blocked)" => build_env(
      path: "/admin/users"
    ),
    "GraphQL mutation" => build_env(
      method: "POST",
      path: "/graphql",
      headers: {
        "Authorization" => "Bearer #{VALID_JWT}",
        "Content-Type" => "application/json"
      },
      body: '{"query":"mutation { createUser(name: \"test\") { id } }"}'
    ),
    "Search endpoint" => build_env(
      path: "/api/v2/search",
      query_string: "q=enterprise+middleware&page=1&per_page=20"
    ),
    "Expired JWT request" => build_env(
      method: "POST",
      path: "/api/v2/orders",
      headers: { "Authorization" => "Bearer #{EXPIRED_JWT}" }
    ),
  }
end

# ---------------------------------------------------------------------------
# Formatting helpers
# ---------------------------------------------------------------------------
def format_ns(ns)
  if ns >= 1_000_000
    "%.2f ms" % (ns / 1_000_000.0)
  elsif ns >= 1_000
    "%.2f \u00b5s" % (ns / 1_000.0)
  else
    "%d ns" % ns
  end
end

def separator(char = "\u2500", width = 100)
  char * width
end

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main
  puts "=" * 100
  puts "Rack::Attack Native Engine Benchmark"
  puts "=" * 100
  puts
  puts "Ruby:          #{RUBY_DESCRIPTION}"
  puts "Rack::Attack:  #{Rack::Attack::VERSION}"
  puts "Rack:          #{Rack.release}"
  puts "Date:          #{Time.now.strftime('%Y-%m-%d %H:%M:%S %z')}"
  puts

  # -- Load native rules ---------------------------------------------------
  rules_data = JSON.parse(File.read(File.expand_path("rules.json", __dir__)))
  # Inject RSA public key for JWT signature verification
  rules_data["jwt_keys"] = [
    { "algorithm" => "RS256", "key" => RSA_PUBLIC.to_pem }
  ]
  rules_json = JSON.generate(rules_data)
  native_ruleset = RackAttackNative::RuleSet.from_json(rules_json)
  puts "Native engine: #{native_ruleset.rule_count} compiled rules (includes JWT)"

  # -- Configure Ruby rules ------------------------------------------------
  configure_ruby_rules!

  config = Rack::Attack.configuration
  n_ruby_rules = config.safelists.size + config.blocklists.size + config.throttles.size + config.tracks.size
  puts "Ruby engine:   #{n_ruby_rules} rules (includes JWT, excludes Fail2Ban)"
  puts

  # -- Build scenarios -----------------------------------------------------
  scenarios = build_scenarios
  middleware = Rack::Attack.new(INNER_APP)

  # Pre-compute native request data for each scenario
  native_requests = scenarios.transform_values { |env| env_to_native(env) }

  # ========================================================================
  # PART 1: Marshalling overhead measurement
  # ========================================================================
  puts separator("=")
  puts "PART 1: Marshalling Overhead (Ruby Hash -> Rust struct)"
  puts separator("=")
  puts

  sample_env = scenarios.values.first
  sample_native = native_requests.values.first

  # Measure just the data conversion cost
  iterations = 50_000
  t0 = Process.clock_gettime(Process::CLOCK_MONOTONIC, :nanosecond)
  iterations.times { env_to_native(sample_env) }
  t1 = Process.clock_gettime(Process::CLOCK_MONOTONIC, :nanosecond)
  marshal_ruby_ns = (t1 - t0).to_f / iterations

  puts "  env_to_native (Ruby-side prep):  #{format_ns(marshal_ruby_ns)}/call"

  # Measure the serde_magnus deserialization + evaluation combined
  # vs just evaluation (to isolate marshalling)
  t0 = Process.clock_gettime(Process::CLOCK_MONOTONIC, :nanosecond)
  iterations.times { native_ruleset.evaluate(sample_native) }
  t1 = Process.clock_gettime(Process::CLOCK_MONOTONIC, :nanosecond)
  native_total_ns = (t1 - t0).to_f / iterations

  puts "  Native evaluate (incl. serde):   #{format_ns(native_total_ns)}/call"
  puts

  # ========================================================================
  # PART 1b: JWT Cost Breakdown (unverified vs verified)
  # ========================================================================
  puts separator("=")
  puts "PART 1b: JWT Cost Breakdown"
  puts separator("=")
  puts
  puts "  Isolates JWT overhead by comparing rulesets with identical non-JWT rules"
  puts "  but different JWT field access patterns."
  puts

  jwt_request_env = build_env(
    method: "POST",
    path: "/api/v2/orders",
    headers: {
      "Authorization" => "Bearer #{VALID_JWT}",
      "X-Api-Key" => "key_abc123",
      "Content-Type" => "application/json"
    },
    cookies: { "_session_id" => "deadbeef" * 8 },
    body: '{"item":"widget","qty":1}'
  )
  jwt_native_req = env_to_native(jwt_request_env)

  # Ruleset with NO JWT rules (baseline)
  no_jwt_data = rules_data.dup
  no_jwt_data["rules"] = no_jwt_data["rules"].reject { |r| r["name"].start_with?("jwt-") }
  no_jwt_data.delete("jwt_keys")
  no_jwt_ruleset = RackAttackNative::RuleSet.from_json(JSON.generate(no_jwt_data))

  # Ruleset with ONLY unverified JWT fields (jwt.payload, jwt.header)
  unverified_jwt_data = rules_data.dup
  unverified_jwt_data["rules"] = no_jwt_data["rules"] + [
    {
      "name" => "jwt-sub-throttle",
      "type" => "throttle",
      "limit" => 100, "period" => 60,
      "key" => ["jwt.payload[\"sub\"]"],
      "condition" => {
        "and" => [
          { "field" => "http.request.uri.path", "operator" => "starts_with", "value" => "/api/" },
          { "field" => "jwt.payload[\"sub\"]", "operator" => "exists" }
        ]
      }
    },
    {
      "name" => "jwt-wrong-audience",
      "type" => "track",
      "condition" => {
        "and" => [
          { "field" => "jwt.payload[\"aud\"]", "operator" => "exists" },
          { "field" => "jwt.payload[\"aud\"]", "operator" => "ne", "value" => "api.example.com" }
        ]
      }
    }
  ]
  unverified_jwt_data.delete("jwt_keys")  # no keys needed for unverified
  unverified_jwt_ruleset = RackAttackNative::RuleSet.from_json(JSON.generate(unverified_jwt_data))

  # Ruleset with verified JWT fields (jwt.valid, jwt.verified_payload)
  # This is the full ruleset (same as native_ruleset)
  verified_jwt_ruleset = native_ruleset

  jwt_iterations = 50_000

  # Baseline: no JWT rules
  t0 = Process.clock_gettime(Process::CLOCK_MONOTONIC, :nanosecond)
  jwt_iterations.times { no_jwt_ruleset.evaluate(jwt_native_req) }
  t1 = Process.clock_gettime(Process::CLOCK_MONOTONIC, :nanosecond)
  no_jwt_ns = (t1 - t0).to_f / jwt_iterations

  # Unverified only: jwt.payload["sub"], jwt.payload["aud"]
  t0 = Process.clock_gettime(Process::CLOCK_MONOTONIC, :nanosecond)
  jwt_iterations.times { unverified_jwt_ruleset.evaluate(jwt_native_req) }
  t1 = Process.clock_gettime(Process::CLOCK_MONOTONIC, :nanosecond)
  unverified_ns = (t1 - t0).to_f / jwt_iterations

  # Full verified: jwt.valid + jwt.verified_payload (includes sig check)
  t0 = Process.clock_gettime(Process::CLOCK_MONOTONIC, :nanosecond)
  jwt_iterations.times { verified_jwt_ruleset.evaluate(jwt_native_req) }
  t1 = Process.clock_gettime(Process::CLOCK_MONOTONIC, :nanosecond)
  verified_ns = (t1 - t0).to_f / jwt_iterations

  # Ruby JWT decode (unverified) for comparison
  t0 = Process.clock_gettime(Process::CLOCK_MONOTONIC, :nanosecond)
  jwt_iterations.times { JWT.decode(VALID_JWT, nil, false) }
  t1 = Process.clock_gettime(Process::CLOCK_MONOTONIC, :nanosecond)
  ruby_unverified_ns = (t1 - t0).to_f / jwt_iterations

  # Ruby JWT decode (verified) for comparison
  t0 = Process.clock_gettime(Process::CLOCK_MONOTONIC, :nanosecond)
  jwt_iterations.times { JWT.decode(VALID_JWT, RSA_PUBLIC, true, algorithm: "RS256") }
  t1 = Process.clock_gettime(Process::CLOCK_MONOTONIC, :nanosecond)
  ruby_verified_ns = (t1 - t0).to_f / jwt_iterations

  puts format("  %-45s %12s", "No JWT rules (baseline)", format_ns(no_jwt_ns))
  puts format("  %-45s %12s  (+%s)", "Unverified JWT (base64 decode only)", format_ns(unverified_ns), format_ns(unverified_ns - no_jwt_ns))
  puts format("  %-45s %12s  (+%s)", "Verified JWT (signature check)", format_ns(verified_ns), format_ns(verified_ns - no_jwt_ns))
  puts
  puts format("  %-45s %12s", "Ruby JWT.decode (unverified)", format_ns(ruby_unverified_ns))
  puts format("  %-45s %12s", "Ruby JWT.decode (verified RS256)", format_ns(ruby_verified_ns))
  puts
  puts format("  %-45s %12s", "Native unverified overhead vs baseline", format_ns(unverified_ns - no_jwt_ns))
  puts format("  %-45s %12s", "Native verification overhead vs unverified", format_ns(verified_ns - unverified_ns))
  puts format("  %-45s %9.1fx", "Native unverified vs Ruby unverified", ruby_unverified_ns / [unverified_ns - no_jwt_ns, 1].max)
  puts format("  %-45s %9.1fx", "Native verified vs Ruby verified", ruby_verified_ns / [verified_ns - no_jwt_ns, 1].max)
  puts

  # ========================================================================
  # PART 2: Throughput comparison (benchmark-ips)
  # ========================================================================
  puts separator("=")
  puts "PART 2: Throughput Comparison (iterations/second)"
  puts separator("=")
  puts
  puts "Note: Ruby engine runs through full Rack::Attack middleware (including cache writes)."
  puts "      Native engine evaluates rules only (no cache interaction)."
  puts "      This measures the rule-evaluation speedup, which is the target optimization."
  puts

  Benchmark.ips do |x|
    x.config(time: 5, warmup: 2)

    scenarios.each do |name, base_env|
      native_req = native_requests[name]

      x.report("Ruby:   #{name}") do
        env = base_env.dup
        env.delete("rack.attack.called")
        middleware.call(env)
      end

      x.report("Native: #{name}") do
        native_ruleset.evaluate(native_req)
      end
    end

    x.compare!
  end

  # ========================================================================
  # PART 3: Per-scenario speedup summary
  # ========================================================================
  puts
  puts separator("=")
  puts "PART 3: Per-Scenario Direct Comparison"
  puts separator("=")
  puts

  iterations_per = 5_000
  header = format("  %-35s %12s %12s %10s", "Scenario", "Ruby", "Native", "Speedup")
  puts header
  puts "  " + ("\u2500" * 73)

  speedups = []
  scenarios.each do |name, base_env|
    native_req = native_requests[name]

    # Ruby timing
    t0 = Process.clock_gettime(Process::CLOCK_MONOTONIC, :nanosecond)
    iterations_per.times do
      env = base_env.dup
      env.delete("rack.attack.called")
      middleware.call(env)
    end
    t1 = Process.clock_gettime(Process::CLOCK_MONOTONIC, :nanosecond)
    ruby_avg = (t1 - t0).to_f / iterations_per

    # Native timing
    t0 = Process.clock_gettime(Process::CLOCK_MONOTONIC, :nanosecond)
    iterations_per.times { native_ruleset.evaluate(native_req) }
    t1 = Process.clock_gettime(Process::CLOCK_MONOTONIC, :nanosecond)
    native_avg = (t1 - t0).to_f / iterations_per

    speedup = ruby_avg / [native_avg, 1].max
    speedups << speedup
    puts format("  %-35s %12s %12s %9.1fx", name, format_ns(ruby_avg), format_ns(native_avg), speedup)
  end

  puts
  puts format("  %-35s %12s %12s %9.1fx", "GEOMETRIC MEAN", "", "", geometric_mean(speedups))
  puts

  # ========================================================================
  # PART 4: Correctness spot-check
  # ========================================================================
  puts separator("=")
  puts "PART 4: Correctness Spot-Check"
  puts separator("=")
  puts

  spot_checks = [
    ["Health check (safelisted)", :safelisted, "health-check-endpoints"],
    ["Internal IP (safelisted)", :safelisted, "internal-network"],
    ["Static asset (safelisted)", :safelisted, "static-assets"],
    ["Blocked IP", :blocklisted, "known-bad-ips"],
    ["Blocked User-Agent", :blocklisted, "blocked-user-agents"],
    ["Sensitive path (blocked)", :blocklisted, "sensitive-paths"],
  ]

  all_pass = true
  spot_checks.each do |scenario_name, expected_key, expected_value|
    native_req = native_requests[scenario_name]
    result = native_ruleset.evaluate(native_req)
    actual = result[expected_key]
    status = actual == expected_value ? "PASS" : "FAIL"
    all_pass = false if status == "FAIL"
    puts format("  [%s] %-35s expected %s=%s, got %s",
                status, scenario_name, expected_key, expected_value.inspect, actual.inspect)
  end

  puts
  puts all_pass ? "  All spot-checks passed." : "  WARNING: Some spot-checks failed!"
  puts

  # ========================================================================
  # PART 5: Realistic Traffic Simulation (~1M requests)
  # ========================================================================
  puts separator("=")
  puts "PART 5: Realistic Traffic Simulation"
  puts separator("=")
  puts
  puts "  Simulates ~1M requests drawn from a weighted traffic distribution"
  puts "  representing realistic production patterns."
  puts

  # -- Traffic distribution (weights must sum to 100) ----------------------
  # Each entry: [weight, description, env_builder_args]
  traffic_mix = [
    # Normal API traffic (largest segment)
    [30, "API GET (various endpoints)", -> {
      paths = %w[/api/v2/users/42 /api/v2/orders /api/v3/products/100 /api/v2/settings /api/v1/legacy/data]
      build_env(
        path: paths.sample,
        headers: { "X-Api-Key" => "key_abc123", "Origin" => "https://app.example.com" },
        cookies: { "_session_id" => "a1b2c3d4e5f6" * 4 }
      )
    }],
    [12, "API POST with JWT", -> {
      build_env(
        method: "POST",
        path: ["/api/v2/orders", "/api/v2/comments", "/api/v3/events"].sample,
        headers: {
          "Authorization" => "Bearer #{VALID_JWT}",
          "X-Api-Key" => "key_abc123",
          "Content-Type" => "application/json"
        },
        cookies: { "_session_id" => "deadbeef" * 8 },
        body: '{"item":"widget","qty":1}'
      )
    }],
    [8, "API PUT/PATCH (session writes)", -> {
      build_env(
        method: %w[PUT PATCH].sample,
        path: "/api/v2/users/42",
        headers: { "X-Api-Key" => "key_abc123", "Content-Type" => "application/json" },
        cookies: { "_session_id" => "deadbeef" * 8 },
        body: '{"name":"updated"}'
      )
    }],

    # Safelisted traffic (short-circuits early)
    [15, "Static assets (safelisted)", -> {
      exts = %w[.js .css .png .jpg .svg .woff2 .ico]
      build_env(path: "/assets/app-abc123#{exts.sample}")
    }],
    [5, "Health checks (safelisted)", -> {
      build_env(
        path: ["/healthz", "/readiness", "/livez"].sample,
        ip: "10.0.0.1",
        user_agent: "kube-probe/1.25"
      )
    }],
    [3, "Internal network (safelisted)", -> {
      build_env(
        path: "/api/v1/internal/metrics",
        ip: "10.0.#{rand(256)}.#{rand(256)}"
      )
    }],

    # Blocked traffic
    [2, "Blocked IPs", -> {
      build_env(
        path: "/api/v2/users",
        ip: BLOCKED_IPS.sample
      )
    }],
    [2, "Blocked User-Agents", -> {
      bots = ["Mozilla/5.0 (compatible; AhrefsBot/7.0)", "Mozilla/5.0 (compatible; SemrushBot/7)", "MJ12bot/v1.4"]
      build_env(path: "/", user_agent: bots.sample)
    }],
    [1, "Sensitive paths (blocked)", -> {
      paths = %w[/admin/users /internal/debug /.env /wp-admin/login.php]
      build_env(path: paths.sample)
    }],

    # Auth endpoints (heavy throttle evaluation)
    [3, "Login attempts", -> {
      build_env(
        method: "POST",
        path: "/auth/login",
        headers: { "X-Login-Email" => "user#{rand(1000)}@example.com" },
        body: "email=user@example.com&password=secret"
      )
    }],
    [1, "Password reset", -> {
      build_env(method: "POST", path: "/auth/password-reset")
    }],
    [1, "Registration", -> {
      build_env(method: "POST", path: "/auth/register")
    }],

    # Other endpoints
    [4, "GraphQL", -> {
      build_env(
        method: "POST",
        path: "/graphql",
        headers: {
          "Authorization" => "Bearer #{VALID_JWT}",
          "Content-Type" => "application/json"
        },
        body: '{"query":"{ users { id name } }"}'
      )
    }],
    [3, "Search", -> {
      build_env(
        path: "/api/v2/search",
        query_string: "q=product+#{rand(1000)}&page=1&per_page=20"
      )
    }],
    [2, "Webhooks", -> {
      build_env(
        method: "POST",
        path: "/webhooks/stripe",
        headers: { "Content-Type" => "application/json" }
      )
    }],
    [2, "Uploads", -> {
      build_env(
        method: "POST",
        path: "/api/v2/uploads",
        headers: { "Content-Type" => "multipart/form-data" }
      )
    }],

    # Edge cases
    [2, "Expired JWT", -> {
      build_env(
        method: "POST",
        path: "/api/v2/orders",
        headers: { "Authorization" => "Bearer #{EXPIRED_JWT}" }
      )
    }],
    [1, "External origin (throttled)", -> {
      origins = %w[https://evil.com https://competitor.io https://random-site.net]
      build_env(
        path: "/api/v2/users",
        headers: { "Origin" => origins.sample, "X-Api-Key" => "key_ext_456" }
      )
    }],
    [1, "SQL injection probe", -> {
      build_env(
        path: "/api/v2/users",
        query_string: "id=1%20OR%201=1--"
      )
    }],
    [1, "Cookieless API", -> {
      build_env(path: "/api/v2/users/42")
    }],
    [1, "Homepage (no rules match beyond global)", -> {
      build_env(path: "/", ip: "45.33.#{rand(256)}.#{rand(256)}")
    }],
  ]

  total_weight = traffic_mix.sum { |w, _, _| w }
  raise "Traffic weights must sum to 100, got #{total_weight}" unless total_weight == 100

  # -- Pre-generate 1M requests -------------------------------------------
  total_requests = 1_000_000
  puts "  Generating #{total_requests.to_s.gsub(/\B(?=(\d{3})+(?!\d))/, ',')} requests..."
  puts

  # Print traffic distribution
  puts format("  %-40s %8s %10s", "Request Type", "Weight", "Count")
  puts "  " + ("\u2500" * 62)
  traffic_mix.each do |weight, desc, _|
    count = (total_requests * weight / 100.0).round
    puts format("  %-40s %7d%% %10s", desc, weight, count.to_s.gsub(/\B(?=(\d{3})+(?!\d))/, ','))
  end
  puts "  " + ("\u2500" * 62)
  puts format("  %-40s %8s %10s", "TOTAL", "100%", total_requests.to_s.gsub(/\B(?=(\d{3})+(?!\d))/, ','))
  puts

  # Build the request pool: create requests proportionally, then shuffle
  request_pool_envs = []
  request_pool_native = []

  traffic_mix.each do |weight, _desc, builder|
    count = (total_requests * weight / 100.0).round
    count.times do
      env = builder.call
      request_pool_envs << env
      request_pool_native << env_to_native(env)
    end
  end

  # Shuffle for realistic interleaving
  indices = (0...request_pool_envs.size).to_a.shuffle
  shuffled_envs = indices.map { |i| request_pool_envs[i] }
  shuffled_native = indices.map { |i| request_pool_native[i] }

  actual_count = shuffled_envs.size
  puts "  Generated #{actual_count.to_s.gsub(/\B(?=(\d{3})+(?!\d))/, ',')} requests (shuffled)"
  puts

  # -- Run Native ----------------------------------------------------------
  puts "  Running native engine..."
  GC.start
  GC.compact if GC.respond_to?(:compact)

  native_t0 = Process.clock_gettime(Process::CLOCK_MONOTONIC, :nanosecond)
  shuffled_native.each { |req| native_ruleset.evaluate(req) }
  native_t1 = Process.clock_gettime(Process::CLOCK_MONOTONIC, :nanosecond)
  native_total_ms = (native_t1 - native_t0) / 1_000_000.0

  # -- Run Ruby ------------------------------------------------------------
  puts "  Running Ruby engine..."
  GC.start
  GC.compact if GC.respond_to?(:compact)

  ruby_t0 = Process.clock_gettime(Process::CLOCK_MONOTONIC, :nanosecond)
  shuffled_envs.each do |env|
    e = env.dup
    e.delete("rack.attack.called")
    middleware.call(e)
  end
  ruby_t1 = Process.clock_gettime(Process::CLOCK_MONOTONIC, :nanosecond)
  ruby_total_ms = (ruby_t1 - ruby_t0) / 1_000_000.0

  # -- Results -------------------------------------------------------------
  puts
  native_rps = actual_count / (native_total_ms / 1_000.0)
  ruby_rps = actual_count / (ruby_total_ms / 1_000.0)
  speedup = ruby_total_ms / [native_total_ms, 0.001].max
  native_avg_us = (native_t1 - native_t0) / 1_000.0 / actual_count
  ruby_avg_us = (ruby_t1 - ruby_t0) / 1_000.0 / actual_count

  puts format("  %-35s %15s", "Requests processed", actual_count.to_s.gsub(/\B(?=(\d{3})+(?!\d))/, ','))
  puts
  puts format("  %-35s %15s", "", "Ruby            Native")
  puts "  " + ("\u2500" * 62)
  puts format("  %-35s %8.1f ms     %8.1f ms", "Total wall time", ruby_total_ms, native_total_ms)
  puts format("  %-35s %8.2f \u00b5s     %8.2f \u00b5s", "Avg per request", ruby_avg_us, native_avg_us)
  puts format("  %-35s %8s req/s  %8s req/s", "Throughput",
              ruby_rps.round.to_s.gsub(/\B(?=(\d{3})+(?!\d))/, ','),
              native_rps.round.to_s.gsub(/\B(?=(\d{3})+(?!\d))/, ','))
  puts
  puts format("  %-35s %9.2fx", "Overall speedup (Native vs Ruby)", speedup)
  puts
  puts "  Note: Ruby includes full middleware overhead (cache writes, env.dup)."
  puts "        Native measures rule evaluation only (no cache interaction)."
  puts

  # ========================================================================
  # PART 6: Multi-Threaded Scaling (GVL Release Demonstration)
  # ========================================================================
  puts separator("=")
  puts "PART 6: Multi-Threaded Scaling"
  puts separator("=")
  puts
  puts "  Demonstrates that native engine releases the GVL, enabling true"
  puts "  parallelism across Ruby threads. Ruby engine holds the GVL,"
  puts "  so threads serialize (~1x scaling)."
  puts

  thread_counts = [1, 2, 4]
  mt_request_count = [actual_count, 200_000].min  # cap for speed
  mt_native_reqs = shuffled_native[0, mt_request_count]
  mt_envs = shuffled_envs[0, mt_request_count]

  native_baselines = {}
  ruby_baselines = {}

  puts format("  %-10s %12s %12s %10s %12s %12s %10s",
              "Threads", "Native(ms)", "Native RPS", "Scaling", "Ruby(ms)", "Ruby RPS", "Scaling")
  puts "  " + ("\u2500" * 82)

  thread_counts.each do |n_threads|
    slice_size = mt_request_count / n_threads

    # -- Native multi-threaded ---
    GC.start
    native_start = Process.clock_gettime(Process::CLOCK_MONOTONIC, :nanosecond)
    threads = (0...n_threads).map do |i|
      offset = i * slice_size
      reqs = mt_native_reqs[offset, slice_size]
      Thread.new { reqs.each { |req| native_ruleset.evaluate(req) } }
    end
    threads.each(&:join)
    native_end = Process.clock_gettime(Process::CLOCK_MONOTONIC, :nanosecond)
    native_ms = (native_end - native_start) / 1_000_000.0
    native_rps_mt = (slice_size * n_threads) / (native_ms / 1_000.0)
    native_baselines[1] ||= native_rps_mt if n_threads == 1
    native_scaling = native_rps_mt / native_baselines[1]

    # -- Ruby multi-threaded ---
    GC.start
    ruby_start = Process.clock_gettime(Process::CLOCK_MONOTONIC, :nanosecond)
    threads = (0...n_threads).map do |i|
      offset = i * slice_size
      envs = mt_envs[offset, slice_size]
      Thread.new do
        envs.each do |env|
          e = env.dup
          e.delete("rack.attack.called")
          middleware.call(e)
        end
      end
    end
    threads.each(&:join)
    ruby_end = Process.clock_gettime(Process::CLOCK_MONOTONIC, :nanosecond)
    ruby_ms = (ruby_end - ruby_start) / 1_000_000.0
    ruby_rps_mt = (slice_size * n_threads) / (ruby_ms / 1_000.0)
    ruby_baselines[1] ||= ruby_rps_mt if n_threads == 1
    ruby_scaling = ruby_rps_mt / ruby_baselines[1]

    puts format("  %-10d %9.1f ms %12s %9.2fx %9.1f ms %12s %9.2fx",
                n_threads,
                native_ms,
                native_rps_mt.round.to_s.gsub(/\B(?=(\d{3})+(?!\d))/, ','),
                native_scaling,
                ruby_ms,
                ruby_rps_mt.round.to_s.gsub(/\B(?=(\d{3})+(?!\d))/, ','),
                ruby_scaling)
  end

  puts
  puts "  Expected: Native scaling ~Nx (GVL released during evaluation)"
  puts "            Ruby scaling  ~1x (GVL held, threads serialize)"
  puts

  puts separator("=")
  puts "Benchmark complete."
  puts separator("=")
end

def geometric_mean(values)
  return 0 if values.empty?

  (values.reduce(:*)**(1.0 / values.length))
end

main
