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

## UUID checker experiment (Go 1.26.8)

The production UUID regexp was replaced with a fixed-length ASCII checker;
case-insensitive duplicate detection and error messages are unchanged. The old
regexp remains a test-only oracle. Tests cover all 256 byte substitutions at
all 36 positions, version/variant combinations, and arbitrary plus near-valid
fuzz inputs. A 30-second differential fuzz run completed 320,394 executions
without a mismatch. The target is included in the scheduled fuzz matrix.

A same-process microbenchmark (five samples) measured median valid UUID checks
at 702 ns for the original regexp and 129 ns for the ASCII checker; both allocate
zero bytes. These figures describe only the format check, not full user sync.

Full HTTP timings were highly unstable on this machine: an initial sequential
comparison even showed slower overall fetches despite faster validation. Three
alternating baseline (`57f06e4` in a separate worktree)/candidate runs produced:

| Operation | Baseline median | Candidate median |
|---|---:|---:|
| 10,000-user validation | 38.33 ms | 9.69 ms |
| 50,000-user validation | 210.05 ms | 51.18 ms |
| 10,000-user full HTTP fetch | 150.09 ms | 86.25 ms |
| 50,000-user full HTTP fetch | 705.33 ms | 606.15 ms |

These runs had wide ranges (50,000-user HTTP: baseline 579–848 ms, candidate
391–732 ms), so **no stable endpoint speedup percentage is claimed**. The
localized format-check improvement is supported by the same-process comparison;
end-to-end gains must be remeasured on a quiet host before making capacity claims.

```sh
go test ./pkg -run '^$' -bench '^BenchmarkUUIDValidation$' -benchmem -count=5
go test ./pkg -run '^$' -fuzz '^FuzzValidUserUUIDMatchesOriginal$' \
  -fuzztime=30s -parallel=4
```

## Error redaction delimiter guards (after v0.1.2)

The next experiment keeps all existing regexps and their replacement order.
Every pattern requires a literal `:` or `=`; the URL-userinfo pattern also
requires `@`. Missing delimiters allow the corresponding scans to be skipped.
No sensitive-keyword heuristic is used, preserving Unicode case-folding behavior
such as `Key` and `ſecret`. Replacements cannot introduce a previously absent
colon or equals sign, so initial delimiter checks remain safe across the chain.

A test-only copy of the old unguarded sequence serves as the differential oracle.
A 30-second fuzz run completed 54,020 executions without an output mismatch,
including comparison of post-redaction truncation. Existing secret-redaction
and error-formatting regression tests also pass. This is equivalence to the
existing redactor, not a claim that arbitrary secrets can always be identified.

Three-sample same-process medians on Go 1.26.8:

| Synthetic input | Original | Guarded | Guarded allocated/op |
|---|---:|---:|---:|
| Plain 8 KiB | 41.27 ms | 1.05 µs | 0 |
| Query secrets 8 KiB | 48.62 ms | 13.71 ms | 146 KB |
| Near-limit quoted colon secret | 5.05 ms | 3.26 ms | 17 KB |
| Mixed query/colon fields | 53.96 ms | 48.39 ms | 237 KB |

Host timings remain noisy; these are workload-specific microbenchmarks, not
API latency guarantees. Plain text now performs only delimiter scans without
regexp allocation; mixed delimiter input still requires most original work.

```sh
go test ./pkg -run '^$' -bench '^BenchmarkRedactionFastPath$' -benchmem -count=3
go test ./pkg -run '^$' -fuzz '^FuzzRedactionFastPathEquivalent$' -fuzztime=30s
```

## Release gate discovered during baseline work

The GitHub CI run for `8214031` passed testing/lint but failed `govulncheck` with
Go 1.25.11 standard-library vulnerabilities. Secret Scan and CodeQL passed.
The diagnostic lists standard-library fixes through Go 1.25.13 and an associated
`golang.org/x/net/idna` fix in x/net v0.55.0. A separate security update should
select a supported patched Go toolchain, review dependency updates, and rerun
all checks. Benchmark results here used local Go 1.26.3 and do not establish its
security status. Do not suppress the scanner to obtain a green build.

Follow-up: the project toolchain is now Go 1.26.8 (module minimum remains Go
1.25), x/net is v0.56.0, and x/sys is v0.46.0. CI, fuzz and release read the
preferred toolchain from go.mod. The local symbol/package/module vulnerability
scan reports no vulnerabilities. The measurements above remain the historical
Go 1.26.3 baseline and have not been relabeled as results for the new toolchain.
