#!/usr/bin/env ruby
# frozen_string_literal: true

#
# Rack::Attack Realistic HTTP Server Benchmark
#
# Runs actual HTTP requests against two Puma servers:
#   - Port 9001: Standard Rack::Attack middleware (Ruby block rules)
#   - Port 9002: Native Rust rule engine middleware
#
# Usage:
#   cd rack-attack-native && bundle exec rake compile && cd ..
#   ruby benchmark/benchmark_http.rb
#
# Environment variables:
#   REQUESTS=N  — number of requests to run (default: 1,000,000)
#

$LOAD_PATH.unshift File.expand_path("../lib", __dir__)
$LOAD_PATH.unshift File.expand_path("../rack-attack-native/lib", __dir__)

require "rack"
require "rack/attack"
require "rack/attack/version"
require "puma"
require "puma/server"
require "puma/configuration"
require "puma/events"
require "net/http"
require "jwt"
require "json"
require "openssl"
require "ipaddr"
require "stringio"
require "socket"
require "rack_attack_native"

# ---------------------------------------------------------------------------
# Minimal in-memory cache store (same as benchmark_native.rb)
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
# RSA key pair for JWT
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
# Simulated data (same as benchmark_native.rb)
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
# Middleware to override REMOTE_ADDR from X-Real-IP header
# (since all requests arrive via 127.0.0.1 loopback)
# ---------------------------------------------------------------------------
class RealIpOverride
  def initialize(app)
    @app = app
  end

  def call(env)
    if (real_ip = env["HTTP_X_REAL_IP"])
      env["REMOTE_ADDR"] = real_ip
    end
    @app.call(env)
  end
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
# NativeRackAttack middleware — wraps native RuleSet in a Rack middleware
# ---------------------------------------------------------------------------
class NativeRackAttack
  def initialize(app, ruleset, cache_store)
    @app = app
    @ruleset = ruleset
    @cache_store = cache_store
  end

  def call(env)
    request_data = extract_request_data(env)
    result = @ruleset.evaluate(request_data)

    # Handle safelisted
    if result[:safelisted]
      return @app.call(env)
    end

    # Handle blocklisted
    if result[:blocklisted]
      return [403, { "content-type" => "text/plain" }, ["Forbidden"]]
    end

    # Handle throttles — mirror Rack::Attack::Cache#count logic
    if result[:throttle_matches]
      result[:throttle_matches].each do |match|
        name = match[:name]
        discriminator = match[:discriminator]
        next unless discriminator

        limit = match[:limit]
        period = match[:period]
        epoch = (Time.now.to_i / period).to_i
        cache_key = "rack::attack:#{epoch}:#{name}:#{discriminator}"

        count = @cache_store.increment(cache_key, 1)
        unless count
          @cache_store.write(cache_key, 1, expires_in: period)
          count = 1
        end

        if count > limit
          return [429, {
            "content-type" => "text/plain",
            "retry-after" => (period - (Time.now.to_i % period)).to_s
          }, ["Rate Limit Exceeded"]]
        end
      end
    end

    @app.call(env)
  end

  private

  def extract_request_data(env)
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
      ip: env["HTTP_X_REAL_IP"] || env["REMOTE_ADDR"] || "",
      user_agent: env["HTTP_USER_AGENT"],
      host: env["HTTP_HOST"],
      query_string: env["QUERY_STRING"] || "",
      content_length: (env["CONTENT_LENGTH"] || 0).to_i,
      authorization: env["HTTP_AUTHORIZATION"],
      body: body_str,
      headers: headers,
      cookies: cookies,
    }
  end
end

# ---------------------------------------------------------------------------
# Server lifecycle
# ---------------------------------------------------------------------------
RUBY_PORT  = 9001
NATIVE_PORT = 9002

def start_server(port, app)
  pid = fork do
    # Silence Puma output in the child
    $stdout = File.open(File::NULL, "w")
    $stderr = File.open(File::NULL, "w")

    conf = Puma::Configuration.new do |c|
      c.threads 1, 1
      c.workers 0
    end
    conf.clamp

    events = Puma::Events.new
    server = Puma::Server.new(app, events, conf.options)
    server.add_tcp_listener("127.0.0.1", port)
    server.run
    sleep # block forever until killed
  end

  wait_for_server(port)
  pid
end

def wait_for_server(port, timeout: 10)
  deadline = Time.now + timeout
  loop do
    TCPSocket.new("127.0.0.1", port).close
    return
  rescue Errno::ECONNREFUSED, Errno::ECONNRESET
    raise "Server on port #{port} failed to start within #{timeout}s" if Time.now > deadline
    sleep 0.05
  end
end

def stop_server(pid)
  Process.kill("TERM", pid)
  Process.wait(pid)
rescue Errno::ESRCH, Errno::ECHILD
  # already dead
end

# ---------------------------------------------------------------------------
# Traffic mix — same weights and builders as benchmark_native.rb
# ---------------------------------------------------------------------------
def build_traffic_mix
  # Default external IP for most requests
  ext_ip = "203.0.113.1"

  [
    [30, "API GET (various endpoints)", ->(rng) {
      paths = %w[/api/v2/users/42 /api/v2/orders /api/v3/products/100 /api/v2/settings /api/v1/legacy/data]
      { method: "GET", path: paths.sample(random: rng), ip: ext_ip,
        headers: { "X-Api-Key" => "key_abc123", "Origin" => "https://app.example.com" },
        cookies: { "_session_id" => "a1b2c3d4e5f6" * 4 }, query_string: "", body: nil }
    }],
    [12, "API POST with JWT", ->(rng) {
      { method: "POST", path: ["/api/v2/orders", "/api/v2/comments", "/api/v3/events"].sample(random: rng), ip: ext_ip,
        headers: { "Authorization" => "Bearer #{VALID_JWT}", "X-Api-Key" => "key_abc123",
                   "Content-Type" => "application/json" },
        cookies: { "_session_id" => "deadbeef" * 8 },
        query_string: "", body: '{"item":"widget","qty":1}' }
    }],
    [8, "API PUT/PATCH (session writes)", ->(rng) {
      { method: %w[PUT PATCH].sample(random: rng), path: "/api/v2/users/42", ip: ext_ip,
        headers: { "X-Api-Key" => "key_abc123", "Content-Type" => "application/json" },
        cookies: { "_session_id" => "deadbeef" * 8 },
        query_string: "", body: '{"name":"updated"}' }
    }],
    [15, "Static assets (safelisted)", ->(rng) {
      exts = %w[.js .css .png .jpg .svg .woff2 .ico]
      { method: "GET", path: "/assets/app-abc123#{exts.sample(random: rng)}", ip: ext_ip,
        headers: {}, cookies: {}, query_string: "", body: nil }
    }],
    [5, "Health checks (safelisted)", ->(rng) {
      { method: "GET", path: ["/healthz", "/readiness", "/livez"].sample(random: rng), ip: "10.0.0.1",
        headers: { "User-Agent" => "kube-probe/1.25" },
        cookies: {}, query_string: "", body: nil }
    }],
    [3, "Internal network (safelisted)", ->(rng) {
      { method: "GET", path: "/api/v1/internal/metrics", ip: "10.0.#{rng.rand(256)}.#{rng.rand(256)}",
        headers: {}, cookies: {}, query_string: "", body: nil }
    }],
    [2, "Blocked IPs", ->(rng) {
      { method: "GET", path: "/api/v2/users", ip: BLOCKED_IPS.sample(random: rng),
        headers: {}, cookies: {}, query_string: "", body: nil }
    }],
    [2, "Blocked User-Agents", ->(rng) {
      bots = ["Mozilla/5.0 (compatible; AhrefsBot/7.0)", "Mozilla/5.0 (compatible; SemrushBot/7)", "MJ12bot/v1.4"]
      { method: "GET", path: "/", ip: ext_ip,
        headers: { "User-Agent" => bots.sample(random: rng) },
        cookies: {}, query_string: "", body: nil }
    }],
    [1, "Sensitive paths (blocked)", ->(rng) {
      paths = %w[/admin/users /internal/debug /.env /wp-admin/login.php]
      { method: "GET", path: paths.sample(random: rng), ip: ext_ip,
        headers: {}, cookies: {}, query_string: "", body: nil }
    }],
    [3, "Login attempts", ->(rng) {
      { method: "POST", path: "/auth/login", ip: ext_ip,
        headers: { "X-Login-Email" => "user#{rng.rand(1000)}@example.com",
                   "Content-Type" => "application/x-www-form-urlencoded" },
        cookies: {}, query_string: "",
        body: "email=user@example.com&password=secret" }
    }],
    [1, "Password reset", ->(_rng) {
      { method: "POST", path: "/auth/password-reset", ip: ext_ip,
        headers: { "Content-Type" => "application/x-www-form-urlencoded" },
        cookies: {}, query_string: "", body: "email=user@example.com" }
    }],
    [1, "Registration", ->(_rng) {
      { method: "POST", path: "/auth/register", ip: ext_ip,
        headers: { "Content-Type" => "application/x-www-form-urlencoded" },
        cookies: {}, query_string: "", body: "email=new@example.com&password=secret" }
    }],
    [4, "GraphQL", ->(_rng) {
      { method: "POST", path: "/graphql", ip: ext_ip,
        headers: { "Authorization" => "Bearer #{VALID_JWT}", "Content-Type" => "application/json" },
        cookies: {}, query_string: "",
        body: '{"query":"{ users { id name } }"}' }
    }],
    [3, "Search", ->(rng) {
      { method: "GET", path: "/api/v2/search", ip: ext_ip,
        headers: {}, cookies: {},
        query_string: "q=product+#{rng.rand(1000)}&page=1&per_page=20", body: nil }
    }],
    [2, "Webhooks", ->(_rng) {
      { method: "POST", path: "/webhooks/stripe", ip: ext_ip,
        headers: { "Content-Type" => "application/json" },
        cookies: {}, query_string: "", body: '{"event":"payment.completed"}' }
    }],
    [2, "Uploads", ->(_rng) {
      { method: "POST", path: "/api/v2/uploads", ip: ext_ip,
        headers: { "Content-Type" => "multipart/form-data" },
        cookies: {}, query_string: "", body: "file-data-placeholder" }
    }],
    [2, "Expired JWT", ->(_rng) {
      { method: "POST", path: "/api/v2/orders", ip: ext_ip,
        headers: { "Authorization" => "Bearer #{EXPIRED_JWT}", "Content-Type" => "application/json" },
        cookies: {}, query_string: "", body: '{"item":"widget"}' }
    }],
    [1, "External origin (throttled)", ->(rng) {
      origins = %w[https://evil.com https://competitor.io https://random-site.net]
      { method: "GET", path: "/api/v2/users", ip: ext_ip,
        headers: { "Origin" => origins.sample(random: rng), "X-Api-Key" => "key_ext_456" },
        cookies: {}, query_string: "", body: nil }
    }],
    [1, "SQL injection probe", ->(_rng) {
      { method: "GET", path: "/api/v2/users", ip: ext_ip,
        headers: {}, cookies: {},
        query_string: "id=1%20OR%201=1--", body: nil }
    }],
    [1, "Cookieless API", ->(_rng) {
      { method: "GET", path: "/api/v2/users/42", ip: ext_ip,
        headers: {}, cookies: {}, query_string: "", body: nil }
    }],
    [1, "Homepage (no rules match beyond global)", ->(rng) {
      { method: "GET", path: "/", ip: "45.33.#{rng.rand(256)}.#{rng.rand(256)}",
        headers: {}, cookies: {}, query_string: "", body: nil }
    }],
  ]
end

# ---------------------------------------------------------------------------
# HTTP request builder
# ---------------------------------------------------------------------------
def build_net_http_request(spec)
  path = spec[:path]
  path = "#{path}?#{spec[:query_string]}" if spec[:query_string] && !spec[:query_string].empty?

  case spec[:method]
  when "GET"    then req = Net::HTTP::Get.new(path)
  when "POST"   then req = Net::HTTP::Post.new(path)
  when "PUT"    then req = Net::HTTP::Put.new(path)
  when "PATCH"  then req = Net::HTTP::Patch.new(path)
  when "DELETE" then req = Net::HTTP::Delete.new(path)
  else               req = Net::HTTP::Get.new(path)
  end

  # Set headers
  spec[:headers]&.each do |key, value|
    req[key] = value
  end

  # Set cookies
  if spec[:cookies] && !spec[:cookies].empty?
    req["Cookie"] = spec[:cookies].map { |k, v| "#{k}=#{v}" }.join("; ")
  end

  # Set simulated client IP via X-Real-IP header
  req["X-Real-IP"] = spec[:ip] if spec[:ip]

  # Set default user-agent if not overridden
  req["User-Agent"] ||= "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"

  # Set body for POST/PUT/PATCH
  if spec[:body] && !spec[:body].empty?
    req.body = spec[:body]
  end

  req
end

# ---------------------------------------------------------------------------
# Run all requests against a single server
# ---------------------------------------------------------------------------
def run_requests(port, specs)
  response_codes = Hash.new(0)

  Net::HTTP.start("127.0.0.1", port, keep_alive_timeout: 60) do |http|
    specs.each do |spec|
      req = build_net_http_request(spec)
      resp = http.request(req)
      response_codes[resp.code.to_i] += 1
    end
  end

  response_codes
end

# ---------------------------------------------------------------------------
# Formatting helpers
# ---------------------------------------------------------------------------
def format_number(n)
  n.to_s.gsub(/\B(?=(\d{3})+(?!\d))/, ',')
end

def separator(char = "\u2500", width = 72)
  char * width
end

# ---------------------------------------------------------------------------
# Spot-check verification
# ---------------------------------------------------------------------------
def run_spot_checks(ruby_port, native_port)
  ext_ip = "203.0.113.1"

  checks = [
    { desc: "Health check (safelisted)", method: "GET", path: "/healthz", ip: "10.0.0.1",
      headers: { "User-Agent" => "kube-probe/1.25" }, expected: 200 },
    { desc: "Static asset (safelisted)", method: "GET", path: "/assets/app.js", ip: ext_ip,
      headers: {}, expected: 200 },
    { desc: "Normal API GET", method: "GET", path: "/api/v2/users/42", ip: ext_ip,
      headers: { "X-Api-Key" => "key_abc123" }, expected: 200 },
    { desc: "Blocked User-Agent", method: "GET", path: "/", ip: ext_ip,
      headers: { "User-Agent" => "Mozilla/5.0 (compatible; AhrefsBot/7.0)" }, expected: 403 },
    { desc: "Sensitive path (blocked)", method: "GET", path: "/admin/users", ip: ext_ip,
      headers: {}, expected: 403 },
    { desc: "Expired JWT (blocked)", method: "POST", path: "/api/v2/orders", ip: ext_ip,
      headers: { "Authorization" => "Bearer #{EXPIRED_JWT}", "Content-Type" => "application/json" },
      expected: 403 },
  ]

  all_pass = true

  checks.each do |check|
    ruby_code = nil
    native_code = nil

    [ruby_port, native_port].each do |port|
      Net::HTTP.start("127.0.0.1", port) do |http|
        path = check[:path]
        req = case check[:method]
              when "POST" then Net::HTTP::Post.new(path)
              else Net::HTTP::Get.new(path)
              end
        req["X-Real-IP"] = check[:ip]
        req["User-Agent"] = check[:headers]["User-Agent"] || "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"
        check[:headers].each { |k, v| req[k] = v unless k == "User-Agent" }

        resp = http.request(req)
        if port == ruby_port
          ruby_code = resp.code.to_i
        else
          native_code = resp.code.to_i
        end
      end
    end

    ruby_ok = ruby_code == check[:expected]
    native_ok = check[:ruby_only] || native_code == check[:expected]
    status = (ruby_ok && native_ok) ? "PASS" : "FAIL"
    all_pass = false unless ruby_ok && native_ok

    detail = ""
    if check[:ruby_only]
      detail = " (Ruby=#{ruby_code}, Native=#{native_code} [not checked])"
    elsif !(ruby_ok && native_ok)
      detail = " (Ruby=#{ruby_code}, Native=#{native_code})"
    end

    puts format("  [%s] %-40s expected=%d%s", status, check[:desc], check[:expected], detail)
  end

  all_pass
end

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main
  total_requests = (ENV["REQUESTS"] || 1_000_000).to_i

  puts "=" * 72
  puts "Rack::Attack Realistic HTTP Server Benchmark"
  puts "=" * 72
  puts
  puts "Ruby:          #{RUBY_DESCRIPTION}"
  puts "Rack::Attack:  #{Rack::Attack::VERSION}"
  puts "Rack:          #{Rack.release}"
  puts "Puma:          #{Puma::Const::PUMA_VERSION}"
  puts "Date:          #{Time.now.strftime('%Y-%m-%d %H:%M:%S %z')}"
  puts

  # -- Load native rules ---------------------------------------------------
  rules_data = JSON.parse(File.read(File.expand_path("rules.json", __dir__)))
  rules_data["jwt_keys"] = [
    { "algorithm" => "RS256", "key" => RSA_PUBLIC.to_pem }
  ]
  rules_json = JSON.generate(rules_data)
  native_ruleset = RackAttackNative::RuleSet.from_json(rules_json)
  puts "Native engine: #{native_ruleset.rule_count} compiled rules"

  # -- Configure Ruby rules ------------------------------------------------
  configure_ruby_rules!
  config = Rack::Attack.configuration
  n_ruby_rules = config.safelists.size + config.blocklists.size + config.throttles.size + config.tracks.size
  puts "Ruby engine:   #{n_ruby_rules} rules"
  puts

  # -- Build Rack apps -----------------------------------------------------
  ruby_app = RealIpOverride.new(Rack::Attack.new(INNER_APP))
  native_app = RealIpOverride.new(NativeRackAttack.new(INNER_APP, native_ruleset, MemoryStore.new))

  # -- Start servers -------------------------------------------------------
  puts "Starting servers..."
  pids = []

  ruby_pid = start_server(RUBY_PORT, ruby_app)
  pids << ruby_pid
  puts "  Ruby server:   PID #{ruby_pid} on 127.0.0.1:#{RUBY_PORT}"

  native_pid = start_server(NATIVE_PORT, native_app)
  pids << native_pid
  puts "  Native server: PID #{native_pid} on 127.0.0.1:#{NATIVE_PORT}"

  puts "  Servers: Puma (1 worker, 1 thread)"
  puts

  # -- Spot-checks ---------------------------------------------------------
  puts separator("=")
  puts "Correctness Spot-Checks"
  puts separator("=")
  puts

  all_pass = run_spot_checks(RUBY_PORT, NATIVE_PORT)
  puts
  puts all_pass ? "  All spot-checks passed." : "  WARNING: Some spot-checks failed!"
  puts

  # -- Generate traffic ----------------------------------------------------
  traffic_mix = build_traffic_mix
  total_weight = traffic_mix.sum { |w, _, _| w }
  raise "Traffic weights must sum to 100, got #{total_weight}" unless total_weight == 100

  puts separator("=")
  puts "Traffic Generation"
  puts separator("=")
  puts
  puts "  Generating #{format_number(total_requests)} request specs..."
  puts

  puts format("  %-40s %8s %10s", "Request Type", "Weight", "Count")
  puts "  " + ("\u2500" * 62)
  traffic_mix.each do |weight, desc, _|
    count = (total_requests * weight / 100.0).round
    puts format("  %-40s %7d%% %10s", desc, weight, format_number(count))
  end
  puts "  " + ("\u2500" * 62)
  puts format("  %-40s %8s %10s", "TOTAL", "100%", format_number(total_requests))
  puts

  # Pre-generate all request specs with a fixed seed for reproducibility
  seed = (ENV["SEED"] || 42).to_i
  rng = Random.new(seed)
  puts "  Random seed: #{seed} (override with SEED=N)"
  puts

  request_specs = []
  traffic_mix.each do |weight, _desc, builder|
    count = (total_requests * weight / 100.0).round
    count.times { request_specs << builder.call(rng) }  # pass rng for deterministic generation
  end
  request_specs.shuffle!(random: rng)

  actual_count = request_specs.size
  puts "  Generated #{format_number(actual_count)} requests (shuffled)"
  puts

  # -- Warmup --------------------------------------------------------------
  puts "  Warming up servers (100 requests each)..."
  warmup_specs = request_specs.first(100)
  run_requests(RUBY_PORT, warmup_specs)
  run_requests(NATIVE_PORT, warmup_specs)
  puts "  Warmup complete."
  puts

  # -- Run benchmark -------------------------------------------------------
  puts separator("=")
  puts "Running Benchmark"
  puts separator("=")
  puts

  # Run Ruby first
  puts "  Running #{format_number(actual_count)} requests against Ruby server (port #{RUBY_PORT})..."
  GC.start
  GC.compact if GC.respond_to?(:compact)

  ruby_t0 = Process.clock_gettime(Process::CLOCK_MONOTONIC)
  ruby_codes = run_requests(RUBY_PORT, request_specs)
  ruby_t1 = Process.clock_gettime(Process::CLOCK_MONOTONIC)
  ruby_elapsed = ruby_t1 - ruby_t0
  puts "  Ruby done in #{"%.1f" % ruby_elapsed}s"

  # Run Native
  puts "  Running #{format_number(actual_count)} requests against Native server (port #{NATIVE_PORT})..."
  GC.start
  GC.compact if GC.respond_to?(:compact)

  native_t0 = Process.clock_gettime(Process::CLOCK_MONOTONIC)
  native_codes = run_requests(NATIVE_PORT, request_specs)
  native_t1 = Process.clock_gettime(Process::CLOCK_MONOTONIC)
  native_elapsed = native_t1 - native_t0
  puts "  Native done in #{"%.1f" % native_elapsed}s"
  puts

  # -- Results -------------------------------------------------------------
  puts separator("=")
  puts "Results"
  puts separator("=")
  puts

  ruby_rps = actual_count / ruby_elapsed
  native_rps = actual_count / native_elapsed
  ruby_avg_us = ruby_elapsed * 1_000_000.0 / actual_count
  native_avg_us = native_elapsed * 1_000_000.0 / actual_count
  speedup = ruby_elapsed / [native_elapsed, 0.001].max

  puts format("  %-35s %15s", "Requests processed", format_number(actual_count))
  puts
  puts format("  %-35s %15s %15s", "", "Ruby", "Native")
  puts "  " + separator("\u2500", 65)
  puts format("  %-35s %12.1f s  %12.1f s", "Total wall time", ruby_elapsed, native_elapsed)
  puts format("  %-35s %12.2f \u00b5s %12.2f \u00b5s", "Avg per request", ruby_avg_us, native_avg_us)
  puts format("  %-35s %11s req/s %10s req/s", "Throughput",
              format_number(ruby_rps.round), format_number(native_rps.round))
  puts
  puts format("  %-35s %12.2fx", "Overall speedup (Native vs Ruby)", speedup)
  puts

  # Response code distribution
  puts "  Response Code Distribution:"
  puts format("    %-10s %12s %12s", "Code", "Ruby", "Native")
  puts "    " + separator("\u2500", 36)
  all_codes = (ruby_codes.keys + native_codes.keys).uniq.sort
  all_codes.each do |code|
    puts format("    %-10d %12s %12s", code,
                format_number(ruby_codes[code] || 0),
                format_number(native_codes[code] || 0))
  end
  puts

  puts separator("=")
  puts "Benchmark complete."
  puts separator("=")

ensure
  # Clean up servers
  if pids && !pids.empty?
    puts
    puts "Stopping servers..."
    pids.each { |pid| stop_server(pid) }
    puts "Servers stopped."
  end
end

main
