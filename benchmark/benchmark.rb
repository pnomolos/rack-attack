#!/usr/bin/env ruby
# frozen_string_literal: true

#
# Rack::Attack Comprehensive Benchmark
#
# Measures per-request overhead of Rack::Attack with a realistic set of
# enterprise-scale rules, then provides a per-rule execution time breakdown.
#
# Usage:
#   ruby benchmark/benchmark.rb
#
# Dependencies:
#   gem install benchmark-ips jwt
#

$LOAD_PATH.unshift File.expand_path("../lib", __dir__)

require "rack"
require "rack/attack"
require "rack/attack/version"
require "benchmark/ips"
require "jwt"
require "json"
require "openssl"
require "ipaddr"
require "stringio"

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
# Simulated data that an enterprise app would keep in memory
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

BLOCKED_USER_AGENTS = %w[
  AhrefsBot SemrushBot MJ12bot DotBot BLEXBot
].freeze

BLOCKED_UA_PATTERN = /\b(#{BLOCKED_USER_AGENTS.join("|")})\b/i

SENSITIVE_PATH_PATTERN = %r{\A/(admin|internal|debug|monitoring|actuator|\.env|\.git|wp-admin|phpMyAdmin)}i

API_VERSION_PATTERN = %r{\A/api/v[0-9]+/}

STATIC_ASSET_PATTERN = %r{\.(css|js|png|jpg|jpeg|gif|ico|svg|woff2?|ttf|eot|map)\z}i

VALID_SESSION_PATTERN = /\A[a-f0-9]{32,128}\z/

# ---------------------------------------------------------------------------
# Minimalist Rack app
# ---------------------------------------------------------------------------
INNER_APP = ->(_env) { [200, { "content-type" => "text/plain" }, ["OK"]] }

# ---------------------------------------------------------------------------
# Helper to build a Rack env hash
# ---------------------------------------------------------------------------
def build_env(
  method: "GET",
  path: "/",
  ip: "203.0.113.1",
  user_agent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
  headers: {},
  cookies: {},
  query_string: "",
  body: nil
)
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
# Configure Rack::Attack with enterprise-scale rules
# ---------------------------------------------------------------------------
def configure_rules!
  Rack::Attack.enabled = true
  Rack::Attack.clear_configuration
  Rack::Attack.cache.store = MemoryStore.new

  # Disable notifications to isolate rule-evaluation cost
  Rack::Attack.notifier = nil

  # =========================================================================
  # SAFELISTS (checked first — short-circuit on match)
  # =========================================================================

  # 1. Health-check / readiness endpoints (exact path)
  Rack::Attack.safelist("health-check-endpoints") do |req|
    req.path == "/healthz" || req.path == "/readiness" || req.path == "/livez"
  end

  # 2. Internal network CIDR safelist
  Rack::Attack.safelist("internal-network") do |req|
    ip = req.ip
    ip && INTERNAL_CIDRS.any? { |cidr| cidr.include?(ip) }
  rescue IPAddr::InvalidAddressError
    false
  end

  # 3. Static assets bypass (regex)
  Rack::Attack.safelist("static-assets") do |req|
    req.get? && req.path.match?(STATIC_ASSET_PATTERN)
  end

  # 4. Trusted service API key header
  Rack::Attack.safelist("trusted-api-key") do |req|
    req.env["HTTP_X_SERVICE_API_KEY"] == "trusted-internal-service-key-abc123"
  end

  # 5. Load-balancer probes (User-Agent)
  Rack::Attack.safelist("load-balancer-probe") do |req|
    ua = req.user_agent
    ua && (ua.start_with?("ELB-HealthChecker") || ua.start_with?("kube-probe"))
  end

  # =========================================================================
  # BLOCKLISTS (checked after safelists)
  # =========================================================================

  # 6. Known-bad individual IPs
  Rack::Attack.blocklist("known-bad-ips") do |req|
    BLOCKED_IPS.include?(req.ip)
  end

  # 7. Known-bad CIDR ranges
  Rack::Attack.blocklist("known-bad-cidrs") do |req|
    ip = req.ip
    ip && BLOCKED_CIDRS.any? { |cidr| cidr.include?(ip) }
  rescue IPAddr::InvalidAddressError
    false
  end

  # 8. Malicious User-Agent patterns
  Rack::Attack.blocklist("blocked-user-agents") do |req|
    ua = req.user_agent
    ua && ua.match?(BLOCKED_UA_PATTERN)
  end

  # 9. Sensitive path access from non-internal IPs (regex + IP check)
  Rack::Attack.blocklist("sensitive-paths") do |req|
    req.path.match?(SENSITIVE_PATH_PATTERN) &&
      !INTERNAL_CIDRS.any? { |cidr| cidr.include?(req.ip) rescue false }
  end

  # 10. Block requests with suspicious query strings (SQL injection probes)
  Rack::Attack.blocklist("sql-injection-probes") do |req|
    qs = req.query_string
    qs && qs.match?(/(\bunion\b.*\bselect\b|\bor\b\s+1\s*=\s*1|\bdrop\b\s+\btable\b)/i)
  end

  # 11. Block path-traversal attempts
  Rack::Attack.blocklist("path-traversal") do |req|
    req.path.include?("..") || req.path.match?(%r{%2e%2e|%252e}i)
  end

  # 12. Block requests with no User-Agent to API endpoints
  Rack::Attack.blocklist("missing-ua-on-api") do |req|
    req.path.start_with?("/api/") && (req.user_agent.nil? || req.user_agent.empty?)
  end

  # 13. Block non-GET/HEAD/OPTIONS requests to read-only endpoints
  Rack::Attack.blocklist("readonly-endpoint-writes") do |req|
    req.path.start_with?("/api/v1/public/") &&
      !%w[GET HEAD OPTIONS].include?(req.request_method)
  end

  # 14. Block oversized request bodies
  Rack::Attack.blocklist("oversized-body") do |req|
    content_length = req.env["CONTENT_LENGTH"].to_i
    content_length > 10_485_760 # 10 MB
  end

  # 15. Fail2Ban: repeated exploit-like query strings
  Rack::Attack.blocklist("fail2ban-exploit-probes") do |req|
    Rack::Attack::Fail2Ban.filter("exploit-#{req.ip}", maxretry: 3, findtime: 600, bantime: 3600) do
      req.query_string.match?(%r{/etc/passwd|/proc/self|<script|javascript:}i) rescue false
    end
  end

  # =========================================================================
  # THROTTLES (checked after blocklists — require cache)
  # =========================================================================

  # 16. Global per-IP rate limit
  Rack::Attack.throttle("global/ip", limit: 300, period: 60) do |req|
    req.ip
  end

  # 17. Stricter API per-IP limit
  Rack::Attack.throttle("api/ip", limit: 100, period: 60) do |req|
    req.ip if req.path.start_with?("/api/")
  end

  # 18. Login endpoint — per IP (POST only)
  Rack::Attack.throttle("login/ip", limit: 5, period: 60) do |req|
    req.ip if req.post? && req.path == "/auth/login"
  end

  # 19. Login endpoint — per email parameter
  Rack::Attack.throttle("login/email", limit: 5, period: 300) do |req|
    if req.post? && req.path == "/auth/login"
      # Simulate extracting email from parsed body
      req.env["HTTP_X_LOGIN_EMAIL"]&.to_s&.downcase&.strip
    end
  end

  # 20. Password reset — per IP
  Rack::Attack.throttle("password-reset/ip", limit: 3, period: 1800) do |req|
    req.ip if req.post? && req.path == "/auth/password-reset"
  end

  # 21. Registration — per IP
  Rack::Attack.throttle("registration/ip", limit: 3, period: 3600) do |req|
    req.ip if req.post? && req.path == "/auth/register"
  end

  # 22. API search endpoint (expensive queries)
  Rack::Attack.throttle("search/ip", limit: 20, period: 60) do |req|
    req.ip if req.get? && req.path.match?(%r{\A/api/v[0-9]+/search\z})
  end

  # 23. File upload endpoint
  Rack::Attack.throttle("upload/ip", limit: 10, period: 300) do |req|
    req.ip if req.post? && req.path.match?(%r{\A/api/v[0-9]+/uploads\z})
  end

  # 24. GraphQL endpoint (mutation-heavy)
  Rack::Attack.throttle("graphql/ip", limit: 60, period: 60) do |req|
    req.ip if req.post? && req.path == "/graphql"
  end

  # 25. Webhook receiver
  Rack::Attack.throttle("webhooks/ip", limit: 30, period: 60) do |req|
    req.ip if req.post? && req.path.start_with?("/webhooks/")
  end

  # 26-30. Exponential back-off for brute force (5 levels)
  (1..5).each do |level|
    Rack::Attack.throttle("auth-bruteforce/level-#{level}", limit: (6 * level), period: (30 ** level)) do |req|
      req.ip if req.post? && req.path == "/auth/login"
    end
  end

  # 31. Per-user API throttle (via JWT subject claim in header)
  Rack::Attack.throttle("api/user-token", limit: 200, period: 60) do |req|
    if req.path.start_with?("/api/") && req.env["HTTP_AUTHORIZATION"]&.start_with?("Bearer ")
      token = req.env["HTTP_AUTHORIZATION"][7..]
      begin
        payload, _header = JWT.decode(token, RSA_PUBLIC, true, algorithm: "RS256")
        payload["sub"]
      rescue JWT::DecodeError
        nil
      end
    end
  end

  # 32. Cookie-based session throttle
  Rack::Attack.throttle("session/writes", limit: 30, period: 60) do |req|
    if %w[POST PUT PATCH DELETE].include?(req.request_method)
      cookies = parse_cookies(req.env["HTTP_COOKIE"])
      session_id = cookies["_session_id"]
      session_id if session_id && session_id.match?(VALID_SESSION_PATTERN)
    end
  end

  # 33. API key-based throttle (header)
  Rack::Attack.throttle("api/key", limit: 1000, period: 3600) do |req|
    req.env["HTTP_X_API_KEY"] if req.path.start_with?("/api/")
  end

  # 34. Throttle by Origin header (CORS abuse prevention)
  Rack::Attack.throttle("origin/rate", limit: 100, period: 60) do |req|
    origin = req.env["HTTP_ORIGIN"]
    origin if origin && !origin.end_with?(".example.com")
  end

  # =========================================================================
  # TRACKS (checked last — monitoring only)
  # =========================================================================

  # 35. Track API version distribution (regex)
  Rack::Attack.track("api-version") do |req|
    req.path.match?(API_VERSION_PATTERN)
  end

  # 36. Track admin access
  Rack::Attack.track("admin-access") do |req|
    req.path.start_with?("/admin")
  end

  # 37. Track deprecated endpoint usage
  Rack::Attack.track("deprecated-endpoints") do |req|
    req.path.start_with?("/api/v1/") && req.path.match?(%r{/api/v1/(legacy|old|deprecated)})
  end

  # 38. Track high request rates (potential DDoS — with throttle-style limit)
  Rack::Attack.track("high-rate-monitor", limit: 500, period: 60) do |req|
    req.ip
  end

  # 39. Track non-standard HTTP methods
  Rack::Attack.track("unusual-methods") do |req|
    !%w[GET POST PUT PATCH DELETE HEAD OPTIONS].include?(req.request_method)
  end

  # 40. Track requests with JWT but wrong audience
  Rack::Attack.track("jwt-wrong-audience") do |req|
    if req.env["HTTP_AUTHORIZATION"]&.start_with?("Bearer ")
      token = req.env["HTTP_AUTHORIZATION"][7..]
      begin
        payload, _header = JWT.decode(token, RSA_PUBLIC, true, algorithm: "RS256")
        payload["aud"] != "api.example.com"
      rescue JWT::DecodeError
        false
      end
    end
  end

  # 41. Track cookie-less API requests
  Rack::Attack.track("cookieless-api") do |req|
    req.path.start_with?("/api/") && (req.env["HTTP_COOKIE"].nil? || req.env["HTTP_COOKIE"].empty?)
  end

  # 42. Track geo-suspicious IP ranges (simulated with CIDR check)
  suspicious_ranges = %w[45.0.0.0/8 46.0.0.0/8].map { |c| IPAddr.new(c) }
  Rack::Attack.track("geo-suspicious") do |req|
    ip = req.ip
    ip && suspicious_ranges.any? { |cidr| cidr.include?(ip) rescue false }
  end
end

# ---------------------------------------------------------------------------
# Lightweight cookie parser (avoids pulling in full Rack::Utils for parsing)
# ---------------------------------------------------------------------------
def parse_cookies(cookie_string)
  return {} unless cookie_string
  cookie_string.split("; ").each_with_object({}) do |pair, hash|
    key, value = pair.split("=", 2)
    hash[key] = value
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
# Per-rule timing measurement
# ---------------------------------------------------------------------------
RuleTiming = Struct.new(:name, :type, :total_ns, :call_count, keyword_init: true)

def measure_rule_times(scenarios, iterations: 500)
  rule_timings = {}
  config = Rack::Attack.configuration

  # Collect all rules in evaluation order
  rules = []
  config.safelists.each { |name, r| rules << [:safelist, name, r] }
  config.blocklists.each { |name, r| rules << [:blocklist, name, r] }
  config.throttles.each { |name, r| rules << [:throttle, name, r] }
  config.tracks.each { |name, r| rules << [:track, name, r] }

  rules.each do |type, name, _rule|
    rule_timings[name] = RuleTiming.new(name: name, type: type, total_ns: 0, call_count: 0)
  end

  # We also time anonymous safelists/blocklists
  config.instance_variable_get(:@anonymous_safelists).each_with_index do |_r, i|
    name = "(anonymous safelist ##{i})"
    rules.unshift([:anonymous_safelist, name, nil])
    rule_timings[name] = RuleTiming.new(name: name, type: :safelist, total_ns: 0, call_count: 0)
  end
  config.instance_variable_get(:@anonymous_blocklists).each_with_index do |_r, i|
    name = "(anonymous blocklist ##{i})"
    rules << [:anonymous_blocklist, name, nil]
    rule_timings[name] = RuleTiming.new(name: name, type: :blocklist, total_ns: 0, call_count: 0)
  end

  scenarios.each do |scenario_name, base_env|
    iterations.times do
      # For each rule, time its matched_by? call independently.
      # We pass a fresh request each time (rules annotate the env).
      rules.each do |type, name, rule|
        env = base_env.dup
        env.delete("rack.attack.called")
        env.delete("rack.attack.matched")
        env.delete("rack.attack.match_type")
        env.delete("rack.attack.match_data")
        env.delete("rack.attack.match_discriminator")
        env.delete("rack.attack.throttle_data")
        request = Rack::Attack::Request.new(env)

        actual_rule = rule
        if type == :anonymous_safelist
          idx = name.match(/#(\d+)/)[1].to_i
          actual_rule = config.instance_variable_get(:@anonymous_safelists)[idx]
        elsif type == :anonymous_blocklist
          idx = name.match(/#(\d+)/)[1].to_i
          actual_rule = config.instance_variable_get(:@anonymous_blocklists)[idx]
        end

        t0 = Process.clock_gettime(Process::CLOCK_MONOTONIC, :nanosecond)
        actual_rule.matched_by?(request)
        t1 = Process.clock_gettime(Process::CLOCK_MONOTONIC, :nanosecond)

        timing = rule_timings[name]
        timing.total_ns += (t1 - t0)
        timing.call_count += 1
      end
    end
  end

  rule_timings
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

def separator(char = "─", width = 100)
  char * width
end

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main
  puts "=" * 100
  puts "Rack::Attack Comprehensive Benchmark"
  puts "=" * 100
  puts
  puts "Ruby:          #{RUBY_DESCRIPTION}"
  puts "Rack::Attack:  #{Rack::Attack::VERSION}"
  puts "Rack:          #{Rack.release}"
  puts "JWT:           #{JWT.gem_version}"
  puts "Date:          #{Time.now.strftime('%Y-%m-%d %H:%M:%S %z')}"
  puts

  # -- Configure rules -----------------------------------------------------
  configure_rules!

  config = Rack::Attack.configuration
  n_safelists  = config.safelists.size + config.instance_variable_get(:@anonymous_safelists).size
  n_blocklists = config.blocklists.size + config.instance_variable_get(:@anonymous_blocklists).size
  n_throttles  = config.throttles.size
  n_tracks     = config.tracks.size
  total_rules  = n_safelists + n_blocklists + n_throttles + n_tracks

  puts "Rules configured: #{total_rules} total"
  puts "  Safelists:  #{n_safelists}"
  puts "  Blocklists: #{n_blocklists}"
  puts "  Throttles:  #{n_throttles}"
  puts "  Tracks:     #{n_tracks}"
  puts

  # -- Build scenarios and middleware stack ---------------------------------
  scenarios = build_scenarios
  middleware = Rack::Attack.new(INNER_APP)

  puts separator("=")
  puts "PART 1: Throughput (iterations/second via benchmark-ips)"
  puts separator("=")
  puts

  # Baseline — bare Rack app with no middleware
  # Per-scenario — full middleware evaluation
  Benchmark.ips do |x|
    x.config(time: 5, warmup: 2)

    x.report("Baseline (no middleware)") do
      env = scenarios.values.sample.dup
      INNER_APP.call(env)
    end

    scenarios.each do |name, base_env|
      x.report(name) do
        env = base_env.dup
        env.delete("rack.attack.called")
        middleware.call(env)
      end
    end

    x.compare!
  end

  # -- Part 2: Per-rule breakdown ------------------------------------------
  puts
  puts separator("=")
  puts "PART 2: Per-Rule Execution Time Breakdown"
  puts separator("=")
  puts
  puts "Averaging over 500 iterations x #{scenarios.size} scenarios = #{500 * scenarios.size} calls per rule"
  puts

  timings = measure_rule_times(scenarios, iterations: 500)

  # Group by type and sort by avg time descending within each group
  grouped = timings.values.group_by(&:type)

  [:safelist, :blocklist, :throttle, :track].each do |type|
    rules_for_type = grouped[type] || []
    next if rules_for_type.empty?

    puts separator("─")
    puts "  #{type.to_s.upcase}S"
    puts separator("─")
    puts

    header = format("  %-45s %12s %12s %10s", "Rule", "Avg/call", "Total", "Calls")
    puts header
    puts "  " + ("─" * 83)

    rules_for_type.sort_by { |r| -(r.total_ns.to_f / [r.call_count, 1].max) }.each do |r|
      avg_ns = r.call_count > 0 ? r.total_ns.to_f / r.call_count : 0
      puts format("  %-45s %12s %12s %10d",
                   r.name,
                   format_ns(avg_ns),
                   format_ns(r.total_ns),
                   r.call_count)
    end
    puts
  end

  # -- Summary: top 10 most expensive rules --------------------------------
  puts separator("=")
  puts "TOP 10 MOST EXPENSIVE RULES (by average per-call time)"
  puts separator("=")
  puts

  all_sorted = timings.values.sort_by { |r| -(r.total_ns.to_f / [r.call_count, 1].max) }

  header = format("  %-4s %-45s %-12s %12s", "#", "Rule", "Type", "Avg/call")
  puts header
  puts "  " + ("─" * 77)

  all_sorted.first(10).each_with_index do |r, i|
    avg_ns = r.call_count > 0 ? r.total_ns.to_f / r.call_count : 0
    puts format("  %-4d %-45s %-12s %12s", i + 1, r.name, r.type, format_ns(avg_ns))
  end

  puts
  puts separator("=")
  puts "Benchmark complete."
  puts separator("=")
end

main
