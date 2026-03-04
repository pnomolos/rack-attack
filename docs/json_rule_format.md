# JSON Rule Format

Rack::Attack supports defining rules in a declarative JSON format, inspired by [Cloudflare's Ruleset Engine](https://developers.cloudflare.com/ruleset-engine/). JSON rules are a first-class alternative to the traditional Ruby block DSL, offering several advantages:

- **Declarative**: Rules are data, not code. They can be stored in files, databases, or fetched from APIs.
- **Portable**: The same rule definitions work across Ruby and Rust evaluation engines.
- **Optionally accelerated**: When the [`rack-attack-native`](#native-engine-acceleration) gem is installed, JSON rules are automatically evaluated via a compiled Rust engine for significantly better performance.
- **Composable**: JSON rules work alongside traditional block-based DSL rules in the same application.

## Table of Contents

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

### `load_ruleset(source, replace:, jwt_keys:)`

```ruby
Rack::Attack.load_ruleset(source, replace: false, jwt_keys: nil)
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `source` | String, Hash | *(required)* | File path (ending in `.json`), JSON string, or Ruby Hash |
| `replace` | Boolean | `false` | If `true`, clears all existing rules before loading |
| `jwt_keys` | Array | `nil` | Override JWT key configuration (see [JWT Configuration](#jwt-configuration)) |

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
| `condition` | object or null | yes | The condition tree to evaluate (see [Conditions](#conditions)). `null` means "always match". |
| `limit` | integer | throttle only | Maximum number of requests allowed in the period. |
| `period` | integer | throttle only | Time window in seconds. |
| `key` | array of strings | throttle only | Field names used to build the throttle discriminator (see [Fields](#fields)). Defaults to `["ip.src"]`. |

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

Combinators nest freely:

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
| `http.request.body.size` | Body size from Content-Length (numeric, returned as string) |
| `http.request.body.json["key"]` | Value from JSON-parsed body. The body must be valid JSON. |

**Note**: Body fields read and rewind `rack.input`. They are safe to use with downstream middleware that also reads the body.

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
| `eq` | Exact equality | string | `"value": "/api"` |
| `ne` | Not equal | string | `"value": "/api"` |
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

**`wildcard`** uses `File.fnmatch` with `FNM_PATHNAME` (or `glob-match` in the native engine). The `*` character matches any characters within a single path segment.

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
