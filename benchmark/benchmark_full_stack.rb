#!/usr/bin/env ruby
# frozen_string_literal: true

#
# Rack::Attack Full-Stack Benchmark
#
# Compares the full production pipeline for Ruby vs Native rule evaluation:
#   - Ruby:   middleware.call(env) — creates Request, evaluates rules, writes cache
#   - Native: Request.new(env) → NativeBridge.request_to_native(request, required_fields) → evaluate(data)
#
# This benchmark captures the conditional field marshalling optimization (Opt 1)
# that benchmark_native.rb misses by pre-computing native request data.
#
# Usage:
#   cd rack-attack-native && bundle exec rake compile && cd ..
#   ruby benchmark/benchmark_full_stack.rb
#   ITERATIONS=500000 ruby benchmark/benchmark_full_stack.rb
#

$LOAD_PATH.unshift File.expand_path("../lib", __dir__)
$LOAD_PATH.unshift File.expand_path("../rack-attack-native/lib", __dir__)

require "rack"
require "rack/attack"
require "rack/attack/version"
require "rack/attack/native_bridge"
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
# RSA key pair for JWT benchmarks
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
# Full marshal: sends all fields unconditionally (old behavior)
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
# Configure Ruby Rack::Attack rules (identical to benchmark_native.rb)
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
        payload = JWT.decode(token, nil, false).first
        if payload["sub"]
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
# Build representative request scenarios (identical to benchmark_native.rb)
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
# Traffic distribution (identical to benchmark_native.rb)
# ---------------------------------------------------------------------------
def build_traffic_mix
  [
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

def geometric_mean(values)
  return 0 if values.empty?

  (values.reduce(:*)**(1.0 / values.length))
end

def commaify(n)
  n.to_s.gsub(/\B(?=(\d{3})+(?!\d))/, ',')
end

# ---------------------------------------------------------------------------
# Native full-pipeline helper — the actual production code path
# ---------------------------------------------------------------------------
def native_full_pipeline(env, native_ruleset, required_fields)
  request = Rack::Attack::Request.new(env)
  native_data = Rack::Attack::NativeBridge.request_to_native(request, required_fields)
  native_ruleset.evaluate(native_data)
end

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main
  iterations = (ENV["ITERATIONS"] || 100_000).to_i

  puts "=" * 100
  puts "Rack::Attack Full-Stack Benchmark"
  puts "=" * 100
  puts
  puts "Ruby:          #{RUBY_DESCRIPTION}"
  puts "Rack::Attack:  #{Rack::Attack::VERSION}"
  puts "Rack:          #{Rack.release}"
  puts "Iterations:    #{commaify(iterations)} per scenario"
  puts "Date:          #{Time.now.strftime('%Y-%m-%d %H:%M:%S %z')}"
  puts

  # -- Load native rules ---------------------------------------------------
  rules_data = JSON.parse(File.read(File.expand_path("rules.json", __dir__)))
  rules_data["jwt_keys"] = [
    { "algorithm" => "RS256", "key" => RSA_PUBLIC.to_pem }
  ]
  rules_json = JSON.generate(rules_data)
  native_ruleset = RackAttackNative::RuleSet.from_json(rules_json)
  required_fields = native_ruleset.required_fields.to_set

  puts "Native engine: #{native_ruleset.rule_count} compiled rules"
  puts "Required fields: #{required_fields.to_a.sort.join(', ')}"
  puts

  # -- Configure Ruby rules ------------------------------------------------
  configure_ruby_rules!
  config = Rack::Attack.configuration
  n_ruby_rules = config.safelists.size + config.blocklists.size + config.throttles.size + config.tracks.size
  puts "Ruby engine:   #{n_ruby_rules} rules"
  puts

  # -- Build scenarios -----------------------------------------------------
  scenarios = build_scenarios
  middleware = Rack::Attack.new(INNER_APP)

  # Pre-compute native data for eval-only reference
  native_requests_full = scenarios.transform_values { |env| env_to_native(env) }

  # ========================================================================
  # PART 1: Marshalling Comparison (Full vs Conditional)
  # ========================================================================
  puts separator("=")
  puts "PART 1: Marshalling Comparison (Full vs Conditional)"
  puts separator("=")
  puts
  puts "  Compares marshalling strategies with Request already constructed"
  puts "  (mirrors production: middleware creates Request before native bridge)."
  puts
  puts "    Full:        env_to_native(env) — sends all fields unconditionally"
  puts "    Conditional: request_to_native(request, required_fields) — sends only needed fields"
  puts
  puts "  Current ruleset requires: #{required_fields.to_a.sort.join(', ')}"
  puts "  (#{required_fields.size}/8 field categories — worst case for conditional marshalling)"
  puts

  marshal_iterations = [iterations, 50_000].min

  # Part 1a: Current ruleset (nearly all fields required)
  puts "  1a. Current ruleset (#{required_fields.size}/8 fields required):"
  puts
  header = format("    %-33s %12s %12s %10s", "Scenario", "Full", "Conditional", "Savings")
  puts header
  puts "    " + ("\u2500" * 71)

  scenarios.each do |name, env|
    request = Rack::Attack::Request.new(env)

    # Full marshal timing
    t0 = Process.clock_gettime(Process::CLOCK_MONOTONIC, :nanosecond)
    marshal_iterations.times { env_to_native(env) }
    t1 = Process.clock_gettime(Process::CLOCK_MONOTONIC, :nanosecond)
    full_ns = (t1 - t0).to_f / marshal_iterations

    # Conditional marshal timing (Request pre-constructed, like production)
    t0 = Process.clock_gettime(Process::CLOCK_MONOTONIC, :nanosecond)
    marshal_iterations.times do
      Rack::Attack::NativeBridge.request_to_native(request, required_fields)
    end
    t1 = Process.clock_gettime(Process::CLOCK_MONOTONIC, :nanosecond)
    cond_ns = (t1 - t0).to_f / marshal_iterations

    saving_pct = ((full_ns - cond_ns) / full_ns * 100).clamp(-999, 999)
    puts format("    %-33s %12s %12s %9.0f%%", name, format_ns(full_ns), format_ns(cond_ns), saving_pct)
  end

  puts

  # Part 1b: Minimal ruleset (only path/ip — simulates simple config)
  minimal_rules = {
    "rules" => rules_data["rules"].select { |r|
      %w[health-check-endpoints known-bad-ips global/ip].include?(r["name"])
    }
  }
  minimal_ruleset = RackAttackNative::RuleSet.from_json(JSON.generate(minimal_rules))
  minimal_fields = minimal_ruleset.required_fields.to_set

  puts "  1b. Minimal ruleset (path/IP only, #{minimal_fields.size}/8 fields required: #{minimal_fields.to_a.sort.join(', ').then { |s| s.empty? ? 'none' : s }}):"
  puts

  header = format("    %-33s %12s %12s %10s", "Scenario", "Full", "Conditional", "Savings")
  puts header
  puts "    " + ("\u2500" * 71)

  scenarios.each do |name, env|
    request = Rack::Attack::Request.new(env)

    t0 = Process.clock_gettime(Process::CLOCK_MONOTONIC, :nanosecond)
    marshal_iterations.times { env_to_native(env) }
    t1 = Process.clock_gettime(Process::CLOCK_MONOTONIC, :nanosecond)
    full_ns = (t1 - t0).to_f / marshal_iterations

    t0 = Process.clock_gettime(Process::CLOCK_MONOTONIC, :nanosecond)
    marshal_iterations.times do
      Rack::Attack::NativeBridge.request_to_native(request, minimal_fields)
    end
    t1 = Process.clock_gettime(Process::CLOCK_MONOTONIC, :nanosecond)
    cond_ns = (t1 - t0).to_f / marshal_iterations

    saving_pct = ((full_ns - cond_ns) / full_ns * 100).clamp(-999, 999)
    puts format("    %-33s %12s %12s %9.0f%%", name, format_ns(full_ns), format_ns(cond_ns), saving_pct)
  end

  puts

  # ========================================================================
  # PART 2: Full-Stack Per-Scenario Comparison
  # ========================================================================
  puts separator("=")
  puts "PART 2: Full-Stack Per-Scenario Comparison (#{commaify(iterations)} iterations)"
  puts separator("=")
  puts
  puts "  Ruby:             middleware.call(env) — full Rack::Attack pipeline"
  puts "  Native (full):    Request.new + request_to_native + evaluate — production pipeline"
  puts "  Native (eval):    evaluate(pre_computed) — rule evaluation only (reference)"
  puts

  header = format("  %-28s %10s %10s %10s %8s %8s",
                   "Scenario", "Ruby", "Nat Full", "Nat Eval", "Full Spd", "Eval Spd")
  puts header
  puts "  " + ("\u2500" * 88)

  full_speedups = []
  eval_speedups = []

  scenarios.each do |name, base_env|
    native_precomputed = native_requests_full[name]

    # Ruby timing
    GC.start
    t0 = Process.clock_gettime(Process::CLOCK_MONOTONIC, :nanosecond)
    iterations.times do
      env = base_env.dup
      env.delete("rack.attack.called")
      middleware.call(env)
    end
    t1 = Process.clock_gettime(Process::CLOCK_MONOTONIC, :nanosecond)
    ruby_ns = (t1 - t0).to_f / iterations

    # Native full-pipeline timing
    GC.start
    t0 = Process.clock_gettime(Process::CLOCK_MONOTONIC, :nanosecond)
    iterations.times { native_full_pipeline(base_env, native_ruleset, required_fields) }
    t1 = Process.clock_gettime(Process::CLOCK_MONOTONIC, :nanosecond)
    native_full_ns = (t1 - t0).to_f / iterations

    # Native eval-only timing (reference)
    GC.start
    t0 = Process.clock_gettime(Process::CLOCK_MONOTONIC, :nanosecond)
    iterations.times { native_ruleset.evaluate(native_precomputed) }
    t1 = Process.clock_gettime(Process::CLOCK_MONOTONIC, :nanosecond)
    native_eval_ns = (t1 - t0).to_f / iterations

    full_spd = ruby_ns / [native_full_ns, 1].max
    eval_spd = ruby_ns / [native_eval_ns, 1].max
    full_speedups << full_spd
    eval_speedups << eval_spd

    puts format("  %-28s %10s %10s %10s %7.1fx %7.1fx",
                name, format_ns(ruby_ns), format_ns(native_full_ns), format_ns(native_eval_ns),
                full_spd, eval_spd)
  end

  puts "  " + ("\u2500" * 88)
  puts format("  %-28s %10s %10s %10s %7.1fx %7.1fx",
              "GEOMETRIC MEAN", "", "", "",
              geometric_mean(full_speedups), geometric_mean(eval_speedups))
  puts

  # ========================================================================
  # PART 3: Realistic Traffic Simulation
  # ========================================================================
  puts separator("=")
  puts "PART 3: Realistic Traffic Simulation"
  puts separator("=")
  puts
  puts "  Simulates ~1M requests drawn from a weighted traffic distribution."
  puts "  Both Ruby and Native exercise their full production pipelines."
  puts

  traffic_mix = build_traffic_mix
  total_weight = traffic_mix.sum { |w, _, _| w }
  raise "Traffic weights must sum to 100, got #{total_weight}" unless total_weight == 100

  total_requests = 1_000_000
  puts "  Generating #{commaify(total_requests)} requests..."
  puts

  puts format("  %-40s %8s %10s", "Request Type", "Weight", "Count")
  puts "  " + ("\u2500" * 62)
  traffic_mix.each do |weight, desc, _|
    count = (total_requests * weight / 100.0).round
    puts format("  %-40s %7d%% %10s", desc, weight, commaify(count))
  end
  puts "  " + ("\u2500" * 62)
  puts format("  %-40s %8s %10s", "TOTAL", "100%", commaify(total_requests))
  puts

  # Build and shuffle request pool
  request_pool_envs = []
  traffic_mix.each do |weight, _desc, builder|
    count = (total_requests * weight / 100.0).round
    count.times { request_pool_envs << builder.call }
  end
  request_pool_envs.shuffle!

  actual_count = request_pool_envs.size
  puts "  Generated #{commaify(actual_count)} requests (shuffled)"
  puts

  # -- Run Native full pipeline --------------------------------------------
  puts "  Running native engine (full pipeline)..."
  GC.start
  GC.compact if GC.respond_to?(:compact)

  native_t0 = Process.clock_gettime(Process::CLOCK_MONOTONIC, :nanosecond)
  request_pool_envs.each do |env|
    native_full_pipeline(env, native_ruleset, required_fields)
  end
  native_t1 = Process.clock_gettime(Process::CLOCK_MONOTONIC, :nanosecond)
  native_total_ms = (native_t1 - native_t0) / 1_000_000.0

  # -- Run Ruby ------------------------------------------------------------
  puts "  Running Ruby engine..."
  GC.start
  GC.compact if GC.respond_to?(:compact)

  ruby_t0 = Process.clock_gettime(Process::CLOCK_MONOTONIC, :nanosecond)
  request_pool_envs.each do |env|
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

  puts format("  %-35s %15s", "Requests processed", commaify(actual_count))
  puts
  puts format("  %-35s %15s", "", "Ruby            Native")
  puts "  " + ("\u2500" * 62)
  puts format("  %-35s %8.1f ms     %8.1f ms", "Total wall time", ruby_total_ms, native_total_ms)
  puts format("  %-35s %8.2f \u00b5s     %8.2f \u00b5s", "Avg per request", ruby_avg_us, native_avg_us)
  puts format("  %-35s %8s req/s  %8s req/s", "Throughput",
              commaify(ruby_rps.round), commaify(native_rps.round))
  puts
  puts format("  %-35s %9.2fx", "Overall speedup (Native vs Ruby)", speedup)
  puts
  puts "  Note: Both sides exercise full production pipelines."
  puts "        Ruby:   env.dup + middleware.call (Request, rules, cache writes)"
  puts "        Native: Request.new + conditional marshalling + Rust evaluate"
  puts

  # ========================================================================
  # PART 4: Correctness Spot-Check
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
    env = scenarios[scenario_name]
    result = native_full_pipeline(env, native_ruleset, required_fields)
    actual = result[expected_key]
    status = actual == expected_value ? "PASS" : "FAIL"
    all_pass = false if status == "FAIL"
    puts format("  [%s] %-35s expected %s=%s, got %s",
                status, scenario_name, expected_key, expected_value.inspect, actual.inspect)
  end

  puts
  puts all_pass ? "  All spot-checks passed." : "  WARNING: Some spot-checks failed!"
  puts

  puts separator("=")
  puts "Benchmark complete."
  puts separator("=")
end

main
