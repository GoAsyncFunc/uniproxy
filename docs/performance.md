# Performance baseline

Baseline: production code at `8214031`, with the benchmark-only additions in
`pkg/pipeline_bench_test.go`, the 50,000-user HTTP case, and the response-limit
regression test. No production implementation or dependencies were changed.

## Reproduction

Measured on darwin/amd64, Go 1.26.3, reported CPU `Genuine Intel(R) CPU 0000 @
1.70GHz`, GOMAXPROCS 16. Results are local synthetic measurements, not production
latency estimates. Repeat on deployment hardware and the intended patched Go
version before comparing an optimization.

```sh
mkdir -p /tmp/uniproxy-perf

go test ./pkg -run '^$' \
  -bench 'BenchmarkUserPipeline|BenchmarkErrorRedactionInputs|BenchmarkGetUserList' \
  -benchmem -benchtime=300ms -count=3

go test ./pkg -run '^$' \
  -bench 'BenchmarkUserPipeline/users_50000/(decode|validate)$' \
  -benchtime=2s \
  -cpuprofile=/tmp/uniproxy-perf/users.cpu \
  -memprofile=/tmp/uniproxy-perf/users.mem \
  -o /tmp/uniproxy-perf/pkg.test

go tool pprof -top /tmp/uniproxy-perf/users.cpu
go tool pprof -top -alloc_space /tmp/uniproxy-perf/users.mem
```

HTTP benchmarks include the in-process httptest server's allocations. Pipeline
benchmarks exclude fixture creation from timing and measure individual client
operations. Profiles may include fixture setup and runtime work; combined
profiles are not a production workload mix. `B/op` measures cumulative allocated
bytes, not peak retained memory. Do not use race instrumentation for timing.

## Results

Rounded medians of three runs; allocation sizes use decimal MB/KB.

| Operation | Users | Time/op | Allocated/op |
|---|---:|---:|---:|
| HTTP full fetch + parse + validation + copy | 10,000 | 27.82 ms | 9.68 MB |
| HTTP full fetch + parse + validation + copy | 50,000 | 136.09 ms | 49.49 MB |
| HTTP 200, identical body, hash dedup | 10,000 | 5.63 ms | 6.61 MB |
| HTTP 304 + cached copy | 10,000 | 0.300 ms | 426.6 KB |
| JSON decode only | 10,000 | 14.94 ms | 2.32 MB |
| User validation only | 10,000 | 6.56 ms | 732.9 KB |
| SHA-256 only | 10,000 | 2.41 ms | 0 |
| Slice copy only | 10,000 | 0.153 ms | 401.4 KB |
| JSON decode only | 50,000 | 71.88 ms | 13.37 MB |
| User validation only | 50,000 | 37.59 ms | 2.93 MB |
| SHA-256 only | 50,000 | 12.51 ms | 0 |
| Slice copy only | 50,000 | 0.864 ms | 2.01 MB |

The generated 50,000-user JSON is approximately 4.59 MB, below the 8 MiB response
limit. `TestUserResponseExactBodyLimit` independently checks valid JSON padded to
exactly 8 MiB and rejects the same payload one byte over the limit.

### Error redaction

| Input | Median time/op |
|---|---:|
| Plain 8 KiB text | 12.95 ms |
| Repeated secret query fields, 8 KiB | 15.03 ms |
| Unterminated quoted secret, near limit | 1.67 ms |
| Over-limit input | ~2 ns |

Over-limit handling is a constant-time length check and fixed summary; its
reported MB/s is not scanning throughput.

## Profile observations and next experiments

- In the combined 50,000-user decode/validation CPU profile, UUID regexp
  `doOnePass` had 23.4% cumulative sample share. Validation (including duplicate
  maps and regexp matching) had 45.7% cumulative share. These overlapping shares
  must not be added together or interpreted as endpoint latency proportions.
- Allocation hotspots were JSON slice growth, decoded strings, and the two
  duplicate-detection maps. Keep cached slices immutable: do not decode into a
  published cache to save allocations.
- Plain-text error redaction spends substantial CPU in regexp execution and
  case folding. A conservative fast path is worth investigating, with exact
  output comparison, adversarial inputs and fuzz coverage before accepting it.
- An allocation-free UUID format checker is another localized experiment. It
  must preserve the current version/variant, casing, separator and duplicate
  semantics; compare against the existing regexp with fuzz tests.
- Keep returned slice copies. Their safety benefit outweighs their relatively
  small measured time, although their memory cost remains relevant at scale.
- Do not replace Resty or JSON yet. JSON is a real cost, but a library change
  still requires end-to-end benefit and contract compatibility evidence.
- Request coalescing is a separate API/concurrency design decision; measure
  actual overlapping refresh demand before changing cancellation semantics.

## Release gate discovered during baseline work

The GitHub CI run for `8214031` passed testing/lint but failed `govulncheck` with
Go 1.25.11 standard-library vulnerabilities. Secret Scan and CodeQL passed.
The diagnostic lists standard-library fixes through Go 1.25.13 and an associated
`golang.org/x/net/idna` fix in x/net v0.55.0. A separate security update should
select a supported patched Go toolchain, review dependency updates, and rerun
all checks. Benchmark results here used local Go 1.26.3 and do not establish its
security status. Do not suppress the scanner to obtain a green build.
