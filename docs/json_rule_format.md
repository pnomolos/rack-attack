# JSON Rule Format

Rack::Attack supports defining rules in a declarative JSON format, inspired by [Cloudflare's Ruleset Engine](https://developers.cloudflare.com/ruleset-engine/). JSON rules are a first-class alternative to the traditional Ruby block DSL, offering several advantages:

- **Declarative**: Rules are data, not code. They can be stored in files, databases, or fetched from APIs.
- **Portable**: The same rule definitions work across Ruby and Rust evaluation engines.
- **Optionally accelerated**: When the [`rack-attack-native`](#native-engine-acceleration) gem is installed, JSON rules are automatically evaluated via a compiled Rust engine for significantly better performance.
- **Composable**: JSON rules work alongside traditional block-based DSL rules in the same application.

## Table of Contents

- [JSON Schema](#json-schema)
- [Quick Start](#quick-start)
- [Loading Rules](#loading-rules)
  - [`load_ruleset(source, replace:, jwt_keys:)`](#load_rulesetsource-replace-jwt_keys)
  - [Input Formats](#input-formats)
  - [Multiple Loads](#multiple-loads)
  - [Replacing Rules](#replacing-rules)
- [Rule Schema](#rule-schema)
  - [Safelists](#safelists)
  - [Blocklists](#blocklists)
  - [Throttles](#throttles)
  - [Tracks](#tracks)
  - [Enabled/Disabled Rules](#enableddisabled-rules)
  - [Rule Evaluation Order](#rule-evaluation-order)
- [Conditions](#conditions)
  - [Leaf Conditions](#leaf-conditions)
  - [Logical Combinators](#logical-combinators)
  - [Null Conditions](#null-conditions)
- [Fields](#fields)
  - [Network Fields](#network-fields)
  - [HTTP Request Fields](#http-request-fields)
  - [Header, Cookie, and Parameter Fields](#header-cookie-and-parameter-fields)
  - [Body Fields](#body-fields)
  - [JWT Fields](#jwt-fields)
- [Operators](#operators)
  - [String Operators](#string-operators)
  - [Set Operators](#set-operators)
  - [Numeric Operators](#numeric-operators)
  - [IP Network Operators](#ip-network-operators)
  - [Existence Operators](#existence-operators)
  - [Pattern Operators](#pattern-operators)
- [Transforms](#transforms)
- [JWT Configuration](#jwt-configuration)
- [Native Engine Acceleration](#native-engine-acceleration)
- [Interaction with Block-Based Rules](#interaction-with-block-based-rules)
- [Full Example](#full-example)
- [Field Name Reference (Cloudflare Comparison)](#field-name-reference-cloudflare-comparison)
- [Security Considerations](#security-considerations)
  - [JWT Verification Scope](#jwt-verification-scope)
  - [Enforcing Issuer and Audience via Conditions](#enforcing-issuer-and-audience-via-conditions)
  - [ReDoS Risk in the Ruby Fallback Evaluator](#redos-risk-in-the-ruby-fallback-evaluator)
  - [Request Body Size](#request-body-size)
  - [Regex Pattern Safety Recommendations](#regex-pattern-safety-recommendations)
- [Thread Safety](#thread-safety)
- [Code Reloading (Rails Development Mode)](#code-reloading-rails-development-mode)
- [Error Handling](#error-handling)
- [Known Behavioral Differences Between Ruby and Rust Evaluators](#known-behavioral-differences-between-ruby-and-rust-evaluators)

## JSON Schema

A [JSON Schema](json_rule_schema.json) is available for the ruleset format (Draft 2020-12). It provides IDE autocompletion, inline validation, and can be used for CI pre-flight checks without a Ruby runtime.

**Add `$schema` to your ruleset for editor support:**

```json
{
  "$schema": "https://raw.githubusercontent.com/rack/rack-attack/main/docs/json_rule_schema.json",
  "rules": [...]
}
```

Most editors (VS Code, JetBrains, Neovim with LSP) will use the `$schema` property to offer autocompletion and validation automatically.

**Validate in CI:**

```bash
# With check-jsonschema (pip install check-jsonschema)
check-jsonschema --schemafile docs/json_rule_schema.json config/rack_attack_rules.json

# With ajv-cli (npm install -g ajv-cli)
ajv validate -s docs/json_rule_schema.json -d config/rack_attack_rules.json --spec=draft2020
```

> **Note**: The `$schema` property is not part of the ruleset format itself — the native engine and Ruby evaluator both ignore it. It is only used by editors and external validators.
>
> The JSON Schema does not enforce the maximum condition nesting depth of 20 levels. Use `validate_ruleset` or `load_ruleset(source, validate: true)` for full runtime validation including depth checks.

## Quick Start

Create a `rules.json` file:

```json
{
  "rules": [
    {
      "name": "allow-health-checks",
      "type": "safelist",
      "condition": {
        "or": [
          { "field": "http.request.uri.path", "operator": "eq", "value": "/healthz" },
          { "field": "http.request.uri.path", "operator": "eq", "value": "/readiness" }
        ]
      }
    },
    {
      "name": "block-bad-ips",
      "type": "blocklist",
      "condition": {
        "field": "ip.src", "operator": "in",
        "value": ["203.0.113.50", "198.51.100.99"]
      }
    },
    {
      "name": "throttle-api",
      "type": "throttle",
      "limit": 100,
      "period": 60,
      "key": ["ip.src"],
      "condition": {
        "field": "http.request.uri.path", "operator": "starts_with", "value": "/api/"
      }
    }
  ]
}
```

Load it in your initializer:

```ruby
# config/initializers/rack_attack.rb
Rack::Attack.load_ruleset(Rails.root.join("config/rack_attack_rules.json").to_s)
```

## Loading Rules

### `load_ruleset(source, replace:, jwt_keys:, validate:)`

```ruby
Rack::Attack.load_ruleset(source, replace: false, jwt_keys: nil, validate: false)
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `source` | String, Hash | *(required)* | File path (ending in `.json`), JSON string, or Ruby Hash |
| `replace` | Boolean | `false` | If `true`, clears all existing rules before loading |
| `jwt_keys` | Array | `nil` | Override JWT key configuration (see [JWT Configuration](#jwt-configuration)) |
| `validate` | Boolean | `false` | If `true`, validates the ruleset before loading and raises `ArgumentError` on errors |

### Input Formats

**File path** (must end with `.json`):

```ruby
Rack::Attack.load_ruleset("/path/to/rules.json")
```

**JSON string**:

```ruby
json = '{"rules": [{"name": "block-ip", "type": "blocklist", ...}]}'
Rack::Attack.load_ruleset(json)
```

**Ruby Hash** (string or symbol keys):

```ruby
Rack::Attack.load_ruleset({
  rules: [
    { name: "block-ip", type: "blocklist",
      condition: { field: "ip.src", operator: "eq", value: "6.6.6.6" } }
  ]
})
```

### Multiple Loads

Calling `load_ruleset` multiple times appends rules:

```ruby
Rack::Attack.load_ruleset("/path/to/base_rules.json")
Rack::Attack.load_ruleset("/path/to/extra_rules.json")  # adds to existing rules
```

If a rule in the second load has the same `name` as a rule from the first load, the new rule overrides the old one and a warning is emitted. Rule names must be unique across all loads.

JWT key configuration persists across loads: if the first load provides `jwt_keys` and the second does not, the original keys remain available for rules in the second load.

### Replacing Rules

Use `replace: true` to clear all existing rules (including block-based DSL rules) before loading:

```ruby
Rack::Attack.load_ruleset("/path/to/rules.json", replace: true)
```

## Rule Schema

Every rule is a JSON object with at least `name`, `type`, and `condition` fields:

```json
{
  "name": "rule-name",
  "type": "safelist|blocklist|throttle|track",
  "condition": { ... }
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | yes | Unique identifier for the rule. Used in logging and `rack.attack.matched`. |
| `type` | string | yes | One of `"safelist"`, `"blocklist"`, `"throttle"`, or `"track"`. |
| `condition` | object or null | yes (unless `enabled: false`) | The condition tree to evaluate (see [Conditions](#conditions)). `null` means "always match". |
| `limit` | integer | throttle only | Maximum number of requests allowed in the period. |
| `period` | integer | throttle only | Time window in seconds. |
| `key` | array of strings | throttle only | Field names used to build the throttle discriminator (see [Fields](#fields)). Defaults to `["ip.src"]`. |
| `enabled` | boolean | no | Set to `false` to disable a rule without removing it. Defaults to `true`. |
| `description` | string | no | Human-readable description for documentation purposes. Not used during evaluation. |

### Safelists

Safelists have the highest precedence. If any safelist matches, the request is allowed regardless of blocklists or throttles.

```json
{
  "name": "internal-network",
  "type": "safelist",
  "condition": {
    "field": "ip.src", "operator": "in_ip_range",
    "value": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
  }
}
```

### Blocklists

Requests matching any blocklist receive a 403 Forbidden response (customizable via `Rack::Attack.blocklisted_responder`).

```json
{
  "name": "block-scrapers",
  "type": "blocklist",
  "condition": {
    "field": "http.user_agent", "operator": "matches",
    "value": "\\b(ahrefsbot|semrushbot|mj12bot)\\b",
    "transform": "lower"
  }
}
```

### Throttles

Throttles rate-limit requests by counting them against a cache key built from the `key` fields. When the count exceeds `limit` within `period` seconds, the request receives a 429 Too Many Requests response.

```json
{
  "name": "login/ip",
  "type": "throttle",
  "limit": 5,
  "period": 60,
  "key": ["ip.src"],
  "condition": {
    "and": [
      { "field": "http.request.method", "operator": "eq", "value": "POST" },
      { "field": "http.request.uri.path", "operator": "eq", "value": "/auth/login" }
    ]
  }
}
```

The `key` array determines the discriminator. Multiple fields are joined with `:`. For example, `["ip.src", "http.request.headers[\"x-api-key\"]"]` produces a key like `"1.2.3.4:my-api-key"`.

If any key field is absent from the request, the throttle does not match (similar to returning `nil` from a block-based throttle).

### Tracks

Tracks log matching requests via `ActiveSupport::Notifications` without affecting the response.

```json
{
  "name": "admin-access",
  "type": "track",
  "condition": {
    "field": "http.request.uri.path", "operator": "starts_with", "value": "/admin"
  }
}
```

### Enabled/Disabled Rules

Rules can be temporarily disabled without removing them from the ruleset:

```json
{
  "name": "block-scanners",
  "type": "blocklist",
  "enabled": false,
  "description": "Block known vulnerability scanners (disabled during pen testing)",
  "condition": {
    "field": "http.user_agent", "operator": "matches",
    "value": "\\b(nikto|sqlmap|nmap)\\b"
  }
}
```

Disabled rules are completely skipped during evaluation — they have zero runtime cost.

### Rule Evaluation Order

By default, the native engine sorts rules within each type (safelist, blocklist, etc.) by estimated evaluation cost, placing cheaper rules first for faster short-circuit evaluation. You can override this with the top-level `rule_order` field:

```json
{
  "rule_order": "insertion",
  "rules": [...]
}
```

| Value | Description |
|-------|-------------|
| `"cost"` | Sort by estimated evaluation cost, cheapest first (default) |
| `"insertion"` | Preserve the order rules appear in the JSON array |

Cost-based ordering is a micro-optimization that matters most for safelists and blocklists where first-match short-circuiting occurs. For throttles and tracks (which evaluate all matching rules), the ordering has minimal impact. Use `"insertion"` when you need predictable, explicit rule ordering.

**Important notes:**

- **Ordering is per-type, not global.** Regardless of `rule_order`, evaluation always follows: safelists → blocklists → throttles → tracks. The `rule_order` setting controls the ordering of rules *within* each type. For example, with two blocklists in insertion order, the first blocklist in the JSON array is checked first.
- **Native engine only.** Cost-based ordering (`"cost"`) is only implemented in the native Rust engine. The pure Ruby fallback always evaluates rules in insertion order regardless of this setting. If you rely on `rule_order: "insertion"` for correctness (e.g., a specific safelist must be checked first), both engines will produce the correct result.

## Conditions

Conditions are the core of the rule format. Every condition evaluates to true or false against an incoming request.

### Leaf Conditions

A leaf condition compares a single field against a value:

```json
{
  "field": "http.request.uri.path",
  "operator": "starts_with",
  "value": "/api/",
  "transform": "lower"
}
```

| Property | Type | Required | Description |
|----------|------|----------|-------------|
| `field` | string | yes | The request field to extract (see [Fields](#fields)) |
| `operator` | string | yes | Comparison operator (see [Operators](#operators)) |
| `value` | string, number, or array | depends on operator | The value to compare against. Not used by `exists`/`not_exists`. |
| `transform` | string or array | no | Transform(s) to apply to the field value before comparison (see [Transforms](#transforms)) |

### Logical Combinators

Conditions can be composed using `and`, `or`, and `not`:

**`and`** — all sub-conditions must match:

```json
{
  "and": [
    { "field": "http.request.method", "operator": "eq", "value": "POST" },
    { "field": "http.request.uri.path", "operator": "eq", "value": "/auth/login" }
  ]
}
```

**`or`** — at least one sub-condition must match:

```json
{
  "or": [
    { "field": "http.request.uri.path", "operator": "eq", "value": "/healthz" },
    { "field": "http.request.uri.path", "operator": "eq", "value": "/readiness" }
  ]
}
```

**`not`** — negates a single condition:

```json
{
  "not": { "field": "ip.src", "operator": "in_ip_range", "value": ["10.0.0.0/8"] }
}
```

Combinators nest freely (up to a maximum depth of 20 levels):

```json
{
  "and": [
    { "field": "http.request.uri.path", "operator": "starts_with", "value": "/admin" },
    {
      "not": {
        "field": "ip.src", "operator": "in_ip_range",
        "value": ["10.0.0.0/8", "127.0.0.0/8"]
      }
    }
  ]
}
```

### Null Conditions

A `null` condition always evaluates to true. This is useful for throttles that should apply to all requests:

```json
{
  "name": "global/ip",
  "type": "throttle",
  "limit": 300,
  "period": 60,
  "key": ["ip.src"],
  "condition": null
}
```

## Fields

Field names follow a hierarchical dot-notation inspired by [Cloudflare's fields reference](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/). Fields with dynamic keys (headers, cookies, parameters) use bracket notation.

### Network Fields

| Field | Description | Example Value |
|-------|-------------|---------------|
| `ip.src` | Client IP address (respects `X-Forwarded-For` via Rack) | `"203.0.113.50"` |

### HTTP Request Fields

| Field | Description | Example Value |
|-------|-------------|---------------|
| `http.request.method` | HTTP method (uppercase) | `"GET"`, `"POST"` |
| `http.request.uri.path` | Request path | `"/api/v1/users"` |
| `http.request.uri.query` | Raw query string (without `?`) | `"page=2&per=10"` |
| `http.request.uri` | Full URI (path + query string) | `"/search?q=test"` |
| `http.request.uri.path.extension` | File extension from path (without `.`), or nil | `"css"`, `"js"` |
| `http.user_agent` | `User-Agent` header | `"Mozilla/5.0 ..."` |
| `http.host` | `Host` header | `"api.example.com"` |
| `http.request.body.size` | `Content-Length` as integer (returned as string for comparison) | `"1024"` |

### Header, Cookie, and Parameter Fields

These use bracket notation to specify the key:

| Field Pattern | Description | Example |
|---------------|-------------|---------|
| `http.request.headers["name"]` | HTTP request header. The name is case-insensitive and uses hyphens. | `http.request.headers["x-api-key"]` |
| `http.request.cookies["name"]` | Cookie value by name | `http.request.cookies["_session_id"]` |
| `http.request.uri.args["name"]` | Query string parameter by name | `http.request.uri.args["page"]` |

**Header name mapping**: The header name in brackets is matched against Rack's `HTTP_*` environment variables. For example, `http.request.headers["x-api-key"]` reads `env["HTTP_X_API_KEY"]`.

### Body Fields

| Field Pattern | Description |
|---------------|-------------|
| `http.request.body.raw` | Raw request body as a string |
| `http.request.body.json["key"]` | Value from JSON-parsed body. The body must be valid JSON. |
| `http.request.body.json["a.b.c"]` | Nested JSON access. Dots inside the bracket key indicate nesting (equivalent to `body["a"]["b"]["c"]`). |

**Note**: Body fields read and rewind `rack.input`. They are safe to use with downstream middleware that also reads the body.

**Nested JSON example**:

```json
{
  "field": "http.request.body.json[\"user.profile.role\"]",
  "operator": "eq",
  "value": "admin"
}
```

For a request body of `{"user": {"profile": {"role": "admin"}}}`, this condition matches.

**Limitation**: Dots inside the bracket key are always interpreted as nesting separators. There is no escape mechanism for JSON keys that contain literal dots. For example, `http.request.body.json["user.name"]` always navigates to `body["user"]["name"]` and cannot be used to access a top-level key literally named `"user.name"`. If your JSON payloads contain dotted keys, access them via the non-dotted parent key instead.

### JWT Fields

JWT fields provide access to JSON Web Token data from the `Authorization: Bearer <token>` header. Tokens are decoded lazily and cached per-request.

| Field Pattern | Description | Signature Check |
|---------------|-------------|-----------------|
| `jwt.payload["claim"]` | Claim from the JWT payload | No (base64 decode only) |
| `jwt.header["field"]` | Field from the JWT header | No (base64 decode only) |
| `jwt.verified_payload["claim"]` | Claim from signature-verified payload | Yes |
| `jwt.valid` | Returns `"true"` if signature and expiry are valid, nil otherwise | Yes |

**Unverified access** (`jwt.payload`, `jwt.header`) only performs base64 decoding, with no cryptographic verification. This is fast and suitable for routing or logging, but should not be used for authorization decisions.

**Verified access** (`jwt.verified_payload`, `jwt.valid`) requires [JWT configuration](#jwt-configuration) with signing keys. Without configuration, verified fields always return nil.

## Operators

Operators are inspired by [Cloudflare's rule operators](https://developers.cloudflare.com/ruleset-engine/rules-language/operators/).

### String Operators

| Operator | Description | Value Type | Example |
|----------|-------------|------------|---------|
| `eq` | Exact equality | string or number | `"value": "/api"` |
| `ne` | Not equal | string or number | `"value": "/api"` |
| `contains` | Substring match | string | `"value": "admin"` |
| `starts_with` | Prefix match | string | `"value": "/api/"` |
| `ends_with` | Suffix match | string | `"value": ".json"` |

### Set Operators

| Operator | Description | Value Type | Example |
|----------|-------------|------------|---------|
| `in` | Field value is in the array | array of strings | `"value": ["GET", "HEAD"]` |
| `not_in` | Field value is not in the array | array of strings | `"value": ["POST", "PUT"]` |

### Numeric Operators

These convert the field value to a number before comparison. If the field value is not numeric, the condition returns false.

| Operator | Description | Value Type | Example |
|----------|-------------|------------|---------|
| `gt` | Greater than | number | `"value": 10485760` |
| `lt` | Less than | number | `"value": 100` |
| `gte` | Greater than or equal | number | `"value": 1000` |
| `lte` | Less than or equal | number | `"value": 5000` |

`eq` and `ne` also support numeric values and will perform numeric comparison when the value is a number.

### IP Network Operators

| Operator | Description | Value Type | Example |
|----------|-------------|------------|---------|
| `in_ip_range` | IP is within any of the CIDR ranges | string or array of strings | `"value": ["10.0.0.0/8", "172.16.0.0/12"]` |
| `not_in_ip_range` | IP is not within any of the CIDR ranges | string or array of strings | `"value": ["198.18.0.0/15"]` |

Accepts both single IP addresses (`"192.168.1.1"`) and CIDR notation (`"10.0.0.0/8"`).

### Existence Operators

| Operator | Description | Value Type |
|----------|-------------|------------|
| `exists` | Field is present and non-empty | *(none)* |
| `not_exists` | Field is absent or empty | *(none)* |

These operators do not use the `value` property:

```json
{ "field": "http.user_agent", "operator": "not_exists" }
```

### Pattern Operators

| Operator | Description | Value Type | Example |
|----------|-------------|------------|---------|
| `matches` | Ruby regular expression match | string (regex pattern) | `"value": "^/api/v[0-9]+/"` |
| `wildcard` | Glob-style wildcard match (case-sensitive, `*` matches within path segments) | string (glob pattern) | `"value": "/api/*/users/*"` |

**`matches`** uses Ruby's `Regexp` (or Rust's `regex` crate in the native engine). Patterns are not anchored by default; use `^` and `$` for full-string matching.

**`wildcard`** uses `File.fnmatch` with `FNM_PATHNAME` (or `glob-match` in the native engine). The `*` character matches any characters within a single path segment (it does not cross `/` boundaries). Use `**` to match across path segments — for example, `/api/**/users` matches both `/api/v1/users` and `/api/v1/v2/users`.

## Transforms

Transforms modify the extracted field value before the operator is applied. Specify a single transform as a string, or chain multiple transforms as an array (applied left to right).

| Transform | Description | Example |
|-----------|-------------|---------|
| `lower` | Convert to lowercase | `"HELLO"` -> `"hello"` |
| `upper` | Convert to uppercase | `"hello"` -> `"HELLO"` |
| `url_decode` | Percent-decode (`%20` -> space, etc.) | `"hello%20world"` -> `"hello world"` |
| `length` | Replace value with its character length (as a string) | `"hello"` -> `"5"` |

Single transform:

```json
{
  "field": "http.user_agent", "operator": "contains", "value": "ahrefsbot",
  "transform": "lower"
}
```

Chained transforms (applied left to right):

```json
{
  "field": "http.request.uri.query", "operator": "contains", "value": "union select",
  "transform": ["url_decode", "lower"]
}
```

## JWT Configuration

To use verified JWT fields (`jwt.verified_payload`, `jwt.valid`), provide signing keys either in the JSON data or via the `jwt_keys` parameter.

**In the JSON file** (top-level `jwt_keys` array):

```json
{
  "jwt_keys": [
    { "algorithm": "HS256", "key": "your-secret-key" }
  ],
  "rules": [ ... ]
}
```

**Via the `jwt_keys` parameter** (overrides JSON-embedded keys):

```ruby
Rack::Attack.load_ruleset("rules.json", jwt_keys: [
  { "algorithm" => "RS256", "key" => File.read("public_key.pem") }
])
```

**Supported algorithms**: HS256, HS384, HS512, RS256, RS384, RS512, ES256, ES384, PS256, PS384, PS512.

Multiple keys can be provided. During verification, each key is tried in order until one succeeds.

**Note**: Verified JWT access requires the [`jwt`](https://github.com/jwt/ruby-jwt) gem. Without it, `jwt.verified_payload` and `jwt.valid` always return nil.

## Native Engine Acceleration

When the `rack-attack-native` gem is installed and compiled, JSON rules are automatically evaluated via a Rust-based engine that runs without the GVL (Global VM Lock), enabling true parallelism in multi-threaded servers.

```ruby
# Gemfile
gem "rack-attack-native"
```

```bash
# Compile the native extension
cd rack-attack-native && bundle exec rake compile
```

The native engine is a transparent acceleration layer:

- **Detection is automatic**: If `require "rack_attack_native"` succeeds, JSON rules use the Rust engine.
- **Fallback is seamless**: If the native gem is not installed, JSON rules are evaluated in pure Ruby. No code changes needed.
- **Block-based rules are unaffected**: Traditional DSL rules always execute in Ruby regardless of the native engine.
- **Results are identical**: Both engines evaluate the same condition trees with the same semantics.

You can check native engine availability at runtime:

```ruby
Rack::Attack::NativeBridge.available?  # => true or false
```

## Validating Rulesets

Use `validate_ruleset` to check a ruleset for structural errors before loading:

```ruby
result = Rack::Attack.validate_ruleset(source)
result.valid?    # => true or false
result.errors    # => ["Rule #0: missing \"condition\"", ...]
result.warnings  # => ["Rule #1 \"my-rule\": duplicate name...", ...]
```

The `source` parameter accepts the same formats as `load_ruleset` (file path, JSON string, or Ruby Hash). Validation checks rule types, operators, field names, transforms, throttle requirements, condition nesting depth (max 20), and JWT key structure.

**Errors** are critical issues that prevent loading (e.g., missing condition, invalid operator). **Warnings** are informational (e.g., duplicate rule names, unusually high throttle limits). The `valid?` method only checks errors — a ruleset with warnings but no errors is considered valid.

You can also validate automatically during loading:

```ruby
# Raises ArgumentError if validation errors are found
Rack::Attack.load_ruleset(source, validate: true)
```

## Interaction with Block-Based Rules

JSON rules and block-based DSL rules coexist in the same Rack::Attack instance. They follow the same evaluation order: safelists -> blocklists -> throttles -> tracks.

```ruby
# Block-based rule
Rack::Attack.blocklist("dsl-block") { |req| req.ip == "9.9.9.9" }

# JSON rules (loaded alongside)
Rack::Attack.load_ruleset({
  rules: [
    { name: "json-block", type: "blocklist",
      condition: { field: "ip.src", operator: "eq", value: "6.6.6.6" } }
  ]
})

# Both rules are active. A request from 9.9.9.9 or 6.6.6.6 will be blocked.
```

When the native engine is present, JSON rules are evaluated in Rust and block-based rules are evaluated in Ruby. Results from both are combined. Within each rule type (safelist, blocklist, etc.), the semantics are "any match wins" (safelist/blocklist) or "collect all matches" (throttle/track), so evaluation order within a type does not affect correctness.

## Full Example

A production-grade ruleset demonstrating multiple rule types, conditions, and operators:

```json
{
  "jwt_keys": [
    { "algorithm": "HS256", "key": "your-secret-key" }
  ],
  "rules": [
    {
      "name": "health-check-endpoints",
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
      "name": "static-assets",
      "type": "safelist",
      "condition": {
        "and": [
          { "field": "http.request.method", "operator": "eq", "value": "GET" },
          { "field": "http.request.uri.path.extension", "operator": "in",
            "value": ["css", "js", "png", "jpg", "gif", "ico", "svg", "woff", "woff2"] }
        ]
      }
    },
    {
      "name": "known-bad-ips",
      "type": "blocklist",
      "condition": {
        "field": "ip.src", "operator": "in",
        "value": ["203.0.113.50", "198.51.100.99"]
      }
    },
    {
      "name": "block-scrapers",
      "type": "blocklist",
      "condition": {
        "field": "http.user_agent", "operator": "matches",
        "value": "\\b(ahrefsbot|semrushbot|mj12bot|dotbot)\\b",
        "transform": "lower"
      }
    },
    {
      "name": "sensitive-paths",
      "type": "blocklist",
      "condition": {
        "and": [
          { "field": "http.request.uri.path", "operator": "matches",
            "value": "(?i)^/(admin|\\.env|\\.git|wp-admin)" },
          { "not": {
              "field": "ip.src", "operator": "in_ip_range",
              "value": ["10.0.0.0/8", "127.0.0.0/8"]
          }}
        ]
      }
    },
    {
      "name": "sql-injection-probes",
      "type": "blocklist",
      "condition": {
        "field": "http.request.uri.query", "operator": "matches",
        "value": "(\\bunion\\b.*\\bselect\\b|\\bor\\b\\s+1\\s*=\\s*1)",
        "transform": ["url_decode", "lower"]
      }
    },
    {
      "name": "global/ip",
      "type": "throttle",
      "limit": 300,
      "period": 60,
      "key": ["ip.src"],
      "condition": null
    },
    {
      "name": "login/ip",
      "type": "throttle",
      "limit": 5,
      "period": 60,
      "key": ["ip.src"],
      "condition": {
        "and": [
          { "field": "http.request.method", "operator": "eq", "value": "POST" },
          { "field": "http.request.uri.path", "operator": "eq", "value": "/auth/login" }
        ]
      }
    },
    {
      "name": "api/key",
      "type": "throttle",
      "limit": 1000,
      "period": 3600,
      "key": ["http.request.headers[\"x-api-key\"]"],
      "condition": {
        "and": [
          { "field": "http.request.uri.path", "operator": "starts_with", "value": "/api/" },
          { "field": "http.request.headers[\"x-api-key\"]", "operator": "exists" }
        ]
      }
    },
    {
      "name": "jwt-sub-throttle",
      "type": "throttle",
      "limit": 100,
      "period": 60,
      "key": ["jwt.payload[\"sub\"]"],
      "condition": {
        "and": [
          { "field": "http.request.uri.path", "operator": "starts_with", "value": "/api/" },
          { "field": "jwt.payload[\"sub\"]", "operator": "exists" }
        ]
      }
    },
    {
      "name": "admin-access",
      "type": "track",
      "condition": {
        "field": "http.request.uri.path", "operator": "starts_with", "value": "/admin"
      }
    },
    {
      "name": "unusual-methods",
      "type": "track",
      "condition": {
        "field": "http.request.method", "operator": "not_in",
        "value": ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]
      }
    }
  ]
}
```

## Field Name Reference (Cloudflare Comparison)

The field naming convention is inspired by [Cloudflare's fields reference](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/). The table below shows how Rack::Attack fields map to Cloudflare equivalents and to the underlying Rack/Ruby method calls:

| Rack::Attack Field | Cloudflare Equivalent | Ruby Source |
|--------------------|----------------------|-------------|
| `ip.src` | `ip.src` | `request.ip` |
| `http.request.method` | `http.request.method` | `request.request_method` |
| `http.request.uri.path` | `http.request.uri.path` | `request.path` |
| `http.request.uri.query` | `http.request.uri.query` | `request.query_string` |
| `http.request.uri` | `http.request.uri` | path + "?" + query_string |
| `http.request.uri.path.extension` | *(custom)* | `File.extname(request.path)` |
| `http.user_agent` | `http.user_agent` | `request.user_agent` |
| `http.host` | `http.host` | `request.host` |
| `http.request.body.size` | `http.request.body.size` | `request.content_length` |
| `http.request.body.raw` | *(custom)* | `request.body.read` |
| `http.request.headers["k"]` | `http.request.headers["k"]` | `request.env["HTTP_..."]` |
| `http.request.cookies["k"]` | `http.request.cookies["k"]` | `request.cookies[k]` |
| `http.request.uri.args["k"]` | *(custom)* | parsed query string |
| `http.request.body.json["k"]` | *(custom)* | `JSON.parse(body)[k]` |
| `jwt.*` | *(no equivalent)* | JWT decode/verify |

Fields marked *(custom)* are Rack::Attack extensions not present in Cloudflare's rule language. Fields marked *(no equivalent)* have no Cloudflare counterpart because Cloudflare handles JWT at the edge differently.

For more details on Cloudflare's rule language, see:
- [Cloudflare Fields Reference](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/)
- [Cloudflare Rule Operators](https://developers.cloudflare.com/ruleset-engine/rules-language/operators/)
- [Cloudflare Rule Expressions](https://developers.cloudflare.com/ruleset-engine/rules-language/expressions/)

## Security Considerations

### JWT Verification Scope

When the native engine verifies a JWT (accessed via `jwt.verified_payload` or `jwt.valid`), it checks:

1. **Signature** — the token must be signed by one of the configured keys using the expected algorithm.
2. **Expiration** (`exp` claim) — the token must not be expired.

It does **not** automatically validate:

- `iss` (issuer) — which system issued the token
- `aud` (audience) — which service the token is intended for
- `nbf` (not before) — earliest valid time (this claim is not checked)
- Any custom claims

This is by design. Audience and issuer validation are application-specific and are best expressed as explicit rule conditions, keeping the key configuration simple and the verification fast.

> **Important**: Do not rely on `jwt.valid` or `jwt.verified_payload` alone for authorization decisions. Always add conditions to enforce `iss` and/or `aud` when those claims are relevant to your security model.

### Enforcing Issuer and Audience via Conditions

Use `jwt.verified_payload["iss"]` and `jwt.verified_payload["aud"]` in rule conditions to enforce issuer and audience constraints. Because these use `verified_payload`, they require a valid signature — an attacker cannot forge the claim value.

**Example: block requests whose token issuer is not your auth server**

```json
{
  "name": "block-wrong-issuer",
  "type": "blocklist",
  "condition": {
    "and": [
      { "field": "jwt.valid", "operator": "exists" },
      {
        "not": {
          "field": "jwt.verified_payload[\"iss\"]",
          "operator": "eq",
          "value": "https://auth.example.com"
        }
      }
    ]
  }
}
```

**Example: throttle by subject, but only for tokens issued for the API audience**

```json
{
  "name": "api/user",
  "type": "throttle",
  "limit": 500,
  "period": 3600,
  "key": ["jwt.verified_payload[\"sub\"]"],
  "condition": {
    "and": [
      { "field": "jwt.verified_payload[\"aud\"]", "operator": "eq", "value": "api.example.com" },
      { "field": "jwt.verified_payload[\"sub\"]", "operator": "exists" }
    ]
  }
}
```

Note that the `aud` claim may be a JSON array in some token formats. If your tokens use an array audience, check each value individually using `in` or use the `contains` operator against a serialized representation. When in doubt, inspect the raw claim with `jwt.payload["aud"]` (no signature verification) to understand the format your tokens actually produce.

### ReDoS Risk in the Ruby Fallback Evaluator

The `matches` operator evaluates a regular expression against the field value. In the **native (Rust) engine**, patterns are compiled using the `regex` crate, which uses a finite automaton and guarantees linear-time matching regardless of input. It is immune to ReDoS.

In the **Ruby fallback evaluator** (used when `rack-attack-native` is not installed), patterns are evaluated using Ruby's `Regexp` engine (ONIG/PCRE-like). This engine supports backtracking and is vulnerable to **catastrophic backtracking** (ReDoS) if a poorly constructed pattern is combined with adversarial input.

Mitigations when using the Ruby evaluator:

- Keep `matches` patterns simple. Avoid nested quantifiers like `(a+)+` or `(a|aa)+`.
- Use `starts_with`, `ends_with`, `contains`, or `eq` operators instead of `matches` wherever possible — they use plain string operations and are not vulnerable.
- If you need complex patterns only in the native engine, ensure `rack-attack-native` is installed and `Rack::Attack::NativeBridge.available?` returns `true` before deploying regex-heavy rulesets to production.
- Validate patterns in CI using a tool like [regexploit](https://github.com/6e726d/regexploit) or [safe-regex](https://github.com/substack/safe-regex).

### Request Body Size

The `http.request.body.raw` and `http.request.body.json["key"]` fields read the full request body into memory on each evaluation. For applications that accept large uploads, this can cause high memory usage if body-matching rules fire on large requests.

Mitigations:

- Scope body-matching rules narrowly using `and` conditions that first check the path, method, or `Content-Type` header before accessing body fields.
- Guard on size first using `http.request.body.size`:

```json
{
  "and": [
    { "field": "http.request.body.size", "operator": "lt", "value": 65536 },
    { "field": "http.request.body.raw", "operator": "contains", "value": "UNION SELECT" }
  ]
}
```

- Consider setting a maximum body size in your web server or an upstream proxy rather than relying on Rack::Attack alone.

### Regex Pattern Safety Recommendations

When writing `matches` patterns:

- **Prefer anchors**: Use `^` and `$` (or `\A` and `\z` in Ruby) to avoid unintended partial matches. The `matches` operator does not anchor patterns by default.
- **Avoid catastrophic backtracking**: Do not write patterns like `(a*)*`, `(.+)+`, or alternation with shared prefixes like `(foo|foobar)+`.
- **Use literal operators for simple cases**: `starts_with`, `ends_with`, `contains`, and `eq` are faster and safer than equivalent regex.
- **Test with adversarial input**: Before deploying a new `matches` pattern, test it against long strings of repeated characters to confirm it completes quickly.
- **Remember engine differences**: Patterns valid in Ruby's regex engine may not work in the Rust engine (see [Known Behavioral Differences](#known-behavioral-differences-between-ruby-and-rust-evaluators)).

## Thread Safety

Configuration mutations (`load_ruleset`, `clear_configuration`) are protected by a mutex, making them safe to call from any thread. Request evaluation reads a snapshot of the current configuration, so an in-flight request is not affected by concurrent rule changes.

On CRuby (MRI), the GVL provides additional serialization. The mutex also protects JRuby and TruffleRuby deployments where true thread concurrency exists.

**Best practice**: Load your ruleset during application boot (e.g., in a Rails initializer) before the server starts accepting requests. This avoids any concurrent access considerations entirely.

## Code Reloading (Rails Development Mode)

Rack::Attack is loaded via `require` (through Bundler), not autoloaded by Zeitwerk. This means:

- **Configuration survives code reloads.** When Rails reloads autoloaded code in development, `Rack::Attack` and its configuration are not affected.
- **Spring and bootsnap** work correctly. The native Rust extension has no file descriptors or shared memory regions that would break across process preloading.
- **Puma/Unicorn forking** works correctly. The native `RuleSet` contains only owned heap data with no OS-level resources.

### Avoid duplicate rules in `to_prepare` blocks

If you configure Rack::Attack in a `to_prepare` block (which re-runs on every code reload), always use `replace: true` to avoid accumulating duplicate rules:

```ruby
# config/initializers/rack_attack.rb

# WRONG — rules accumulate on every reload:
Rails.application.config.to_prepare do
  Rack::Attack.load_ruleset(Rails.root.join("config/rack_attack_rules.json").to_s)
end

# CORRECT — clears before reloading:
Rails.application.config.to_prepare do
  Rack::Attack.load_ruleset(Rails.root.join("config/rack_attack_rules.json").to_s, replace: true)
end
```

For most applications, configuring in a standard initializer (outside `to_prepare`) is simpler and sufficient.

## Error Handling

Rack::Attack is designed to **fail open** — errors in rule evaluation never block legitimate requests.

### User block errors

If a block-based rule (safelist, blocklist, throttle, or track) raises an exception, the error is logged via `warn` and the rule is treated as non-matching. Other rules continue to evaluate normally.

### Native engine errors

If the native Rust engine raises an error during evaluation (e.g., due to unexpected input), the error is logged and the request proceeds as if no native rules matched. Block-based rules still evaluate normally.

### JWT decode errors

If JWT token decoding or verification fails (malformed token, invalid signature, missing `jwt` gem), the JWT field returns `nil` and evaluation continues. A warning is emitted to help diagnose configuration issues.

### Cache store validation

The cache store is validated when assigned. If the store object is missing required methods (`:read`, `:write`, `:increment`, `:delete`), an `ArgumentError` is raised immediately rather than failing at runtime on the first throttled request.

## Known Behavioral Differences Between Ruby and Rust Evaluators

The Ruby fallback and the native Rust engine aim for identical results, but a small number of edge cases differ.

| Scenario | Ruby Evaluator | Rust (Native) Evaluator | Status |
|----------|---------------|------------------------|--------|
| Regex engine for `matches` operator | Ruby ONIG (PCRE-like): supports backreferences (`\1`), lookahead (`(?=...)`), lookbehind (`(?<=...)`) | Rust `regex` crate (RE2-like): does **not** support backreferences, lookahead, or lookbehind | By design — see below |
| `rule_order: "cost"` | Not implemented — Ruby always evaluates in insertion order | Sorts rules by estimated evaluation cost (cheapest first) | By design |

### Regex Engine Differences in Detail

The most significant behavioral difference is in the `matches` operator's regex engine.

**Ruby (ONIG/PCRE-like)** supports:
- Backreferences: `(foo)\1` matches `"foofoo"`
- Lookahead: `foo(?=bar)` matches `"foo"` only when followed by `"bar"`
- Lookbehind: `(?<=foo)bar` matches `"bar"` only when preceded by `"foo"`
- Possessive quantifiers and atomic groups (via ONIG)

**Rust (`regex` crate / RE2-like)** does **not** support any of the above. Attempting to compile a pattern with these features will cause the condition to return false (the native engine catches the compile error and treats it as non-matching). No runtime panic occurs, but the rule silently does nothing.

**Practical advice**: Write `matches` patterns using only features common to both engines:

- Character classes: `[a-z]`, `\d`, `\w`, `\s`
- Quantifiers: `*`, `+`, `?`, `{n,m}`
- Anchors: `^`, `$`
- Alternation: `(foo|bar)`
- Non-capturing groups: `(?:...)`
- Case-insensitive flag: `(?i)`

Avoid patterns that require PCRE features if you want consistent behavior whether or not the native engine is installed. If you must use PCRE features, accept that the rule will silently not match when the native engine is active, and test both paths explicitly.
