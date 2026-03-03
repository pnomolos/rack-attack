# Rack::Attack Benchmark

A comprehensive benchmark that measures the per-request overhead of `Rack::Attack`
with a realistic set of enterprise-scale rules.

## Running

```bash
ruby benchmark/benchmark.rb
```

## What it measures

The benchmark configures **40+ rules** representative of what a large production
application might use, then measures:

1. **Overall middleware overhead** — how much time Rack::Attack adds per request
   compared to a bare Rack app, measured via `benchmark-ips`.
2. **Per-rule execution time** — a detailed breakdown showing how long each
   individual safelist, blocklist, throttle, and track rule takes to evaluate,
   helping identify expensive matchers.

### Rule categories

| Category | Examples |
|----------|----------|
| IP safelists/blocklists | Internal CIDRs, known-bad IP ranges |
| Path-based matching | Exact path, prefix, and starts-with checks |
| Regex-based matching | Admin paths, API versioning, file extensions |
| HTTP verb matching | POST-only login throttles, write-method blocklists |
| Header inspection | User-Agent, Origin, custom API key headers |
| Cookie / session check | Session token presence and format validation |
| JWT deserialization | Decode + claim verification (exp, iss, aud) |
| Fail2Ban patterns | Suspicious query-string payloads |
| Composite rules | Multi-condition rules combining several matchers |
| Geo / ASN stubs | IP-range checks simulating geo-fencing |

## Dependencies

The benchmark requires the `benchmark-ips` and `jwt` gems:

```bash
gem install benchmark-ips jwt
```
