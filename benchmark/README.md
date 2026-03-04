# Rack::Attack Benchmarks

Comprehensive benchmarks measuring the per-request overhead of `Rack::Attack`
with a realistic set of **42+ enterprise-scale rules** including JWT verification,
CIDR matching, regex blocklists, and throttles.

## Benchmark scripts

### `benchmark.rb` — Ruby middleware overhead

Measures pure Ruby `Rack::Attack` middleware cost per request.

```bash
ruby benchmark/benchmark.rb
```

**What it measures:**
- Overall middleware overhead via `benchmark-ips`
- Per-rule execution time breakdown

### `benchmark_native.rb` — Native engine comparison (eval-only)

Compares Ruby middleware vs native Rust rule engine with pre-computed request data.
Isolates the rule evaluation speedup without marshalling overhead.

```bash
cd rack-attack-native && bundle exec rake compile && cd ..
ruby benchmark/benchmark_native.rb
```

**What it measures:**
- Marshalling overhead (Ruby hash → Rust struct)
- JWT cost breakdown (unverified vs verified decode)
- Per-scenario throughput comparison (`benchmark-ips`)
- Realistic 1M-request traffic simulation
- Multi-threaded scaling (GVL release)

### `benchmark_full_stack.rb` — Full production pipeline comparison

Compares the **actual production code paths** end-to-end:
- **Ruby:** `middleware.call(env)` — creates Request, evaluates rules, writes cache
- **Native:** `Request.new(env)` → `NativeBridge.request_to_native` → `evaluate` — conditional marshalling + Rust evaluation

This captures the conditional field marshalling optimization that `benchmark_native.rb`
misses by pre-computing native request data.

```bash
cd rack-attack-native && bundle exec rake compile && cd ..
ruby benchmark/benchmark_full_stack.rb
ITERATIONS=500000 ruby benchmark/benchmark_full_stack.rb
```

**What it measures:**
- Marshalling comparison: full vs conditional (with minimal-ruleset contrast)
- Per-scenario full-stack speedup (Ruby, Native full pipeline, Native eval-only)
- Realistic 1M-request traffic simulation with both sides exercising full pipelines
- Correctness spot-checks

### `benchmark_http.rb` — Over-the-wire HTTP benchmark

Starts two Puma servers and fires real HTTP requests to compare end-to-end latency
including network I/O, connection handling, and response serialization.

```bash
cd rack-attack-native && bundle exec rake compile && cd ..
ruby benchmark/benchmark_http.rb
REQUESTS=500000 SEED=42 ruby benchmark/benchmark_http.rb
```

## Rule categories

All benchmarks share the same 42-rule configuration (`rules.json`):

| Category | Examples |
|----------|----------|
| IP safelists/blocklists | Internal CIDRs, known-bad IP ranges |
| Path-based matching | Exact path, prefix, and starts-with checks |
| Regex-based matching | Admin paths, API versioning, file extensions |
| HTTP verb matching | POST-only login throttles, write-method blocklists |
| Header inspection | User-Agent, Origin, custom API key headers |
| Cookie / session check | Session token presence and format validation |
| JWT deserialization | Decode + claim verification (exp, iss, aud) |
| Composite rules | Multi-condition rules combining several matchers |
| Geo / ASN stubs | IP-range checks simulating geo-fencing |

## Dependencies

```bash
gem install benchmark-ips jwt
```

The native benchmarks require the `rack-attack-native` extension to be compiled first:

```bash
cd rack-attack-native && bundle exec rake compile && cd ..
```
