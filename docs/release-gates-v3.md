# Schema-v3 collector release gates

The v3 implementation remains a candidate until release validation is complete. On 2026-09-23,
the project accepted a minimum **1.75x** geometric-mean throughput gain in place of the original
2x target. This changes only the aggregate speed target; equivalent coverage, the 5% per-workload
median limit, 10% p95 limit, memory and size limits, and durable delivery requirements remain.
The historical 2x observations below are retained as recorded. The historical adaptive/ultra
benchmark scripts remain informational for v3 because `ultra` no longer changes detector policy.
Use `scripts/bench/release-gate-v3.py` for the four-workload numeric gate, then check the
additional release requirements at the end of this document.

## Paired evidence from 2026-09-22

- Baseline source: `956d509702b48fa967ae0e339ce16f648cf470d2`.
- Candidate: uncommitted working tree based on that SHA. Source-tree content digest, excluding
  `src/pgo/`: `d16f31a2a1808a9c05e9677aab4b24728d0e14e44f022d1eea9fbc60b8c6bcd1`.
- Toolchain: Go 1.26.3 with `GOEXPERIMENT=jsonv2`, `-tags jsonv2`, `-trimpath`, and
  `-ldflags="-s -w"` for stripped release builds. Host: macOS 27.0, Apple M5 Max, ARM64.
- The four paired Go benchmark workloads each have nine samples. Both versions use the
  benchmark's explicit MD5, detector, coverage, concurrency, and output settings; no benefit
  from new defaults is included.
- Process measurements use 30 paired invocations per workload after one priming invocation per
  binary. Corpus content, binary SHA-256 values, and platform are in the local
  `artifacts/bench/release-v3-20260922/process-manifest.json`. These are warm-cache results.
  First-pass observations are separate and **not** a controlled cold-cache measurement.
- Process output signatures matched for retained hashes, search hits, sensitive match counts,
  truncation, warnings, and inspected-byte outcomes on all four corpora. File counts were 128,
  84, 32, and 64 respectively. Record order and v2/v3 envelope identity were not compared.

| Workload | Median throughput speedup | Process p95 ratio | Peak RSS ratio |
|---|---:|---:|---:|
| Small files | 1.068x | 0.944x | 0.927x |
| Mixed heavy tail | 1.152x | 1.004x | 0.922x |
| Sensitive dense | 1.005x | 0.974x | 0.922x |
| Duplicate logs | 0.952x | 0.994x | 0.923x |

Geometric mean throughput speedup is **1.041x**, below the required **2x**. The duplicate-log
median is 5.06% slower, just beyond the 5% workload limit in this local run. Process p95 and
peak RSS remain within their limits on these workloads. This does not establish those limits
for all workloads or on controlled release runners.

| Stripped target | Candidate bytes | Shrink from equally stripped baseline |
|---|---:|---:|
| macOS ARM64 | 15,481,010 | 40.5% |
| macOS AMD64 | 16,528,560 | 39.4% |
| Linux AMD64 | 16,052,386 | 39.9% |
| Linux ARM64 | 14,942,370 | 41.1% |
| Windows AMD64 | 16,584,704 | 39.3% |

The macOS ARM64 binary is 14.76 MiB, below the 16 MiB cap. All other target sizes exceed
the required 30% reduction. Debug-symbol builds are retained under `bin/debug/`.

## Header reuse speed experiment

The next candidate reuses the file-type header in the streaming scan instead of reading
those bytes twice. No detectors, content limits, hash choices, or output requirements changed.
The nine-sample Go benchmark results against the preceding v3 candidate are in
`artifacts/bench/speed-header-20260922/`. Median throughput ratios were 1.020x for small
files, 1.053x for mixed heavy-tail files, 1.094x for sensitive-dense text, and 1.117x for
duplicate logs. Their geometric mean is 1.070x. Against the original frozen source's
benchmark samples, the geometric mean is 1.114x, still below the 2x release gate.

Two separate sets of 30 paired process runs compared the preceding v3 binary with the
header-reuse binary on identical warm-cache corpora. Retained hashes, search hits, sensitive
match counts, truncation, warnings, and inspected-byte outcomes matched in every run.
The first set's duplicate-log p95 ratio was 1.111x, above the 1.10x limit; the repeat was
0.958x. All other workload p95 and peak RSS ratios were within limits in both sets.
The contradictory tail observation remains a reason to verify on controlled runners.
The macOS ARM64 stripped executable remains 15,481,010 bytes. All five targets compiled;
the other target sizes changed by at most 4,096 bytes.

An independent experiment using walker-provided macOS timestamps showed no geometric-mean
benchmark benefit and slowed the duplicate-log median. It was reverted; its raw benchmark
samples are retained as `rejected-times-bench.txt` in the experiment directory.

## Shared search matcher speed experiment

This candidate compiles the exact-search automaton once per scan and shares its
immutable transitions across file workers. Each file keeps separate match state and counts.
For automata with at most 256 nodes, a compact transition table replaces per-byte map lookups;
larger term sets retain the sparse matcher. The nine-sample benchmark evidence is in
`artifacts/bench/speed-sharedaho-20260922/`.

| Workload | Median speedup vs header-only | Allocated bytes ratio |
|---|---:|---:|
| Small files | 1.040x | 0.80x |
| Mixed heavy tail | 1.080x | 0.82x |
| Sensitive dense | 1.180x | 0.95x |
| Duplicate logs | 1.645x | 0.99x |

The geometric mean is 1.215x against header-only and **1.354x** against the original frozen
source's nine benchmark samples. The four workload median speedups against the original
source are 1.132x, 1.309x, 1.297x, and 1.749x respectively. These are local warm-cache
measurements; the 2x release gate remains unmet.

Thirty paired process runs also compared the preceding v3 binary with the current binary.
The two binaries retained identical file evidence on all runs. Median process speedups were
1.012x, 1.561x, 1.319x, and 1.233x in the same workload order. The corresponding p95 ratios
were 0.997x, 0.657x, 0.739x, and 0.822x; peak RSS ratios were 0.993x, 1.006x, 1.003x,
and 0.998x. The process corpus, binary SHA-256 values, and raw samples are in
`artifacts/bench/speed-final-v3-20260922/`.

The stripped macOS ARM64 binary at this stage is 15,481,042 bytes. Other target sizes are
16,532,688 bytes for macOS AMD64, 16,056,482 for Linux AMD64, 14,942,370 for Linux ARM64,
and 16,588,800 for Windows AMD64. All five still satisfy their size gates. `make lint`,
`make test`, macOS scanner race tests, and all five cross-builds pass on this source.

## API-key prefix speed experiment

The current candidate only calls the built-in API-key matcher when a byte is `a` or `A`.
All three recognized key prefixes start with that letter, so this avoids failed token checks
at unrelated letters without changing detector policy. The nine-sample benchmark and 30
paired process runs per workload are in `artifacts/bench/speed-api-prefix-20260922/`.
The benchmark geometric mean improved 1.049x over the preceding candidate and is **1.420x**
against the frozen source. Small-file and sensitive-dense medians were 1.5% and 3.2% slower
in the benchmark; both remain inside the 5% per-workload limit. The paired process runs
retained identical file evidence and all four p95 and peak-RSS ratios passed. The stripped
macOS ARM64 binary remains 15,481,042 bytes, and all five size gates still pass.

## Filesystem bottleneck that motivated the next change

The pre-cache four-workload CPU profile spent about 69% of sampled CPU time in filesystem
syscalls. Resolving each file path with `filepath.EvalSymlinks` accounted for about 21% of
samples, opening files for another 21%, and closing them for about 11%. Exact search was
under 2% of sampled CPU time in that combined profile. These are overlapping profile
attributions, not additive wall-time percentages.

A warm-cache synthetic probe of 1,024 small files measured about 18.6 microseconds per
file for the prior containment check plus open/close, versus 9.0 microseconds using
pre-opened per-directory `os.Root` handles. This only measured the open path; it was not a
scan-throughput or release-gate result. It motivated the bounded directory cache measured
below. Optional path-based collectors keep the guarded fallback, and concurrent directory
renames remain a release concern.

For large logs, profile read syscalls and deterministic sensitive matching separately.
Check chunk size, buffer reuse, and candidate-byte gates with cross-boundary matches and
coverage held fixed. Measure healthy, slow, and disconnected managed export separately;
scan-only improvements do not establish managed-delivery throughput.

## Bounded directory capability experiment

The scanner now caches up to 64 `os.Root` directory handles per scan root and opens each
file relative to its containing directory. The cache is local to one scan, is safe for
concurrent workers, and closes after the scan. Optional path-based xattr, ACL, and ADS
collection, as well as Windows, retain the existing guarded path. A file identity check
rejects a file replaced between traversal and open. Tests cover a parent symlink swap,
an outside symlink leaf, file replacement, timestamp parity, and the handle bound. Failed
opens now produce an explicit file error instead of a partial record. Linux reads birth
and access times from the opened descriptor before content reads can change access time.

Nine-sample Go benchmarks in `artifacts/bench/directory-cache-final-verified-bench.txt` compare
this change with the preceding candidate at the same explicit detector, hash, coverage,
concurrency, and output settings. The medians improved 1.366x for small files, 1.328x for
mixed heavy-tail files, and 1.011x for sensitive-dense text; duplicate logs were 0.988x.
The geometric mean improved **1.160x** over the preceding candidate and **1.647x** against
the frozen source. No workload exceeds the 5% median regression limit in this local run.
The exact uncommitted source digest, toolchain, stripped binary hashes, and size comparisons
are in `artifacts/bench/directory-cache-final-verified-manifest.json`.

Thirty paired warm-cache process runs per workload are in
`artifacts/bench/directory-cache-final-verified-process-20260922/`. Retained hashes,
search hits,
sensitive counts, inspected bytes, truncation, warnings, and file counts matched in every
pair. Against the preceding candidate, process p95 ratios were 0.992, 0.964, 1.060, and
0.927; peak-RSS ratios were 1.018, 0.977, 0.993, and 0.991 in workload order. These pass
the incremental limits but do not establish controlled-runner release acceptance. The
stripped macOS ARM64 binary is 15,581,890 bytes, below 16 MiB. The other four stripped
targets still shrink more than 30% against the equally stripped frozen baseline. All five
targets cross-compiled, and `make lint`, `make test`, macOS scanner race tests, and native
Linux ARM64 scanner/output/config tests passed.

The capability pins the directory that was inside the scan root when opened. If that
directory is renamed during scanning, the scanner can continue reading the pinned
directory, and the recorded pathname can become stale. The outside symlink target is not
read. Concurrent rename behavior needs further adversarial testing before release.

Three separate experiments were retained as evidence but not adopted. Go 1.27.1 gave a
0.994x geometric-mean ratio against the then-current source on Go 1.26.3. Root-wide `os.Root`
opens without a directory cache gave only 1.002x. A direct Unix `openat` variant was
0.909x relative to the directory cache, so it was reverted. Representative-profile PGO
gave 1.042x on top of an earlier directory-cache candidate and 1.743x against the frozen
source. The stripped macOS ARM64 binary was 15,598,306 bytes. Thirty paired PGO process
runs retained the same file evidence, but the small-file p95 ratio was 1.097, close to the
1.10 limit. PGO is still
experimental and predates the final timestamp/error changes: target-specific profiles and
controlled-runner tail checks are required before making it the standard build.

## Bounded close pipeline

A longer sensitive-dense profile showed descriptor closure taking about 28% of sampled CPU,
while deterministic matching took about 7%. The rooted scan path now queues completed file
descriptors to one closer with a 64-file cap per scan root. Workers block when the queue is
full, and scan shutdown drains it before returning success. The path-based fallback still
closes synchronously. A test verifies that cache shutdown waits for pending closes.

Nine samples per workload in `artifacts/bench/bounded-close-candidate-bench.txt` show
median throughput gains of 1.032x, 1.029x, 1.022x, and 1.014x over the preceding
directory-cache candidate. The geometric mean is **1.024x** incremental and **1.687x**
against the frozen source. The exact uncommitted source digest, toolchain, binary hashes,
and sizes are in `artifacts/bench/bounded-close-final-manifest.json`.

Thirty paired warm-cache process runs in `artifacts/bench/bounded-close-process-20260922/`
compared with the candidate before the directory cache. Retained detection, hash, and
coverage evidence matched in every pair. The four p95 ratios were 1.007, 0.972, 1.025,
and 0.999; peak-RSS ratios were 1.025, 1.022, 0.999, and 1.009. The stripped macOS ARM64
binary is 15,581,970 bytes, under 16 MiB. All other targets shrink at least 38.88% from
the equally stripped frozen baseline. `make lint`, `make test`, macOS scanner race tests,
all five cross-builds, and native Linux ARM64 scanner/output/config tests passed on this
source. These are local results; controlled-runner and remaining release checks still apply.

A final single-read experiment for files up to 16 KiB kept file-type decisions on the
original 4 KiB probe, but it was only 1.004x overall and slowed sensitive-dense scans to
0.984x of this candidate. It also increased reads for some limited scans, so it was
reverted. Raw samples remain in `artifacts/bench/small-file-one-read-candidate-bench.txt`.

## Adaptive exact-search experiment

For up to four exact search terms of at most 64 bytes each, the streaming counter uses
Go's byte search with bounded cross-chunk overlap. On large initial chunks, it samples
match density and retains Aho-Corasick when both terms occur frequently. Larger term sets
always use the automaton. Differential tests compare both counters across chunk boundaries,
overlapping terms, and Unicode bytes. No detector, hash, or coverage setting changed.

Nine-sample results in `artifacts/bench/adaptive-byte-search-candidate-bench.txt`
improved the four-workload geometric mean **1.039x** over the bounded-close candidate
and **1.753x** over the frozen source. Duplicate logs improved 1.169x; small files,
mixed heavy-tail, and sensitive-dense ratios were 0.989x, 0.986x, and 1.022x. Thirty
paired warm-cache process runs in `artifacts/bench/adaptive-byte-search-process-20260922/`
retained identical file evidence on every run. Their p95 ratios were 0.979, 0.984,
0.950, and 1.021; peak-RSS ratios were 1.010, 1.006, 0.997, and 1.003 in workload
order. These are local incremental checks, not controlled-runner release evidence.

A separate five-sample search benchmark in
`artifacts/bench/search-algorithms-adaptive-bench.txt` found the dense-term path within
3% of the automaton and the sparse repeated-prefix path 3.3x faster. The stripped macOS
ARM64 binary is 15,582,018 bytes, below the 16 MiB cap. The 2x throughput gate remains
unmet. All five targets cross-compiled; `make lint`, `make test`, macOS scanner/output
race tests, and native Linux ARM64 scanner/output/config tests pass on this source.
The exact source digest, build flags, binary hashes, workload ratios, and remaining gate
state are in `artifacts/bench/adaptive-byte-search-final-manifest.json`. The other four
stripped targets remain at least 38.86% smaller than their equally stripped baselines.

Four parallel descriptor closers measured 0.988x overall, cached-directory `openat`
measured 0.944x, and direct use of the sampled header for small files measured 0.906x
despite lower allocation. Their raw nine-sample results are in
`artifacts/bench/parallel-close-candidate-bench.txt`,
`artifacts/bench/openat-cache-candidate-bench.txt`, and
`artifacts/bench/header-direct-candidate-bench.txt`; none is in the current source.
Small-buffer reuse also measured 0.916x and was reverted. Reusing sorted detector names
measured 1.009x in benchmarks but exceeded the p95 gate for duplicate logs at 1.103x
in 30 paired process runs, so it was reverted too. Their raw results remain under
`artifacts/bench/small-buffer-candidate-bench.txt` and
`artifacts/bench/shared-sensitive-names-process-20260922/`.

A fresh macOS ARM64 profile-guided build of this source measured 1.040x over the
non-PGO build in nine benchmark samples, or 1.823x over the frozen source. Thirty paired
process runs retained the same file evidence; p95 ratios were 1.078, 0.950, 1.012, and
1.011, and the stripped binary size was unchanged. The profile and raw samples are in
`artifacts/bench/adaptive-byte-search-current.pgo`,
`artifacts/bench/adaptive-byte-search-pgo-candidate-bench.txt`, and
`artifacts/bench/adaptive-byte-search-pgo-process-20260922/`. This is a macOS ARM64 build
experiment, not the standard release build: other targets lack native profiles. The original
2x gate was still unmet at the time of this experiment.

## Release-candidate process parity on 2026-09-23

The versioned candidate was run against a fresh stripped binary built from the frozen source.
Thirty warm-cache paired process runs per workload retained identical file evidence in all six
corpora. The two extra corpora exercise wide/deep traversal and bounded-content scans. Corpus and
binary digests, first-pass observations, and raw CSVs are in
`artifacts/bench/release-candidate-20260923/`.

| Workload | Median process speedup | Process p95 ratio | Peak RSS ratio |
|---|---:|---:|---:|
| Small files | 1.169x | 0.909x | 0.938x |
| Mixed heavy tail | 1.856x | 0.550x | 0.919x |
| Sensitive dense | 1.422x | 0.706x | 0.902x |
| Duplicate logs | 1.391x | 0.724x | 0.916x |
| Wide/deep | 1.106x | 0.900x | 0.935x |
| Bounded content | 2.003x | 0.502x | 0.898x |

These process timings are separate from the nine-sample Go benchmark throughput gate. A fresh
benchmark attempt on this host showed a large baseline slowdown inconsistent with the prior run
and was stopped. No speed gate is credited to that incomplete attempt.
The local numeric gate passes at 1.753x using the recorded nine-sample benchmark pair, these
fresh process CSVs, and newly built stripped binaries. Its output is in
`artifacts/bench/release-candidate-20260923/gate-output.txt`. The benchmark pair predates the
shutdown-race fix, which does not change the scan path. This result also predates the toolchain
and dependency update below; it does not certify the updated release binary.

## Security and native-test correction on 2026-09-23

The first PR run found reachable advisories in Go 1.26.3, gRPC 1.80.0, and x/net 0.53.0.
The candidate now uses Go 1.26.8, gRPC 1.83.1, x/net 0.55.0, and OTEL SDK 1.45.0. Local
`govulncheck ./...` reports zero reachable vulnerabilities. Native Windows tests exposed a nil
service handle in the old service-enumeration path and two tests for a rooted-open path that
is disabled on Windows. Service status now uses the Windows service manager directly. Windows
file identity is pinned during traversal so the fallback open can reject a changed pathname.
This corrected an additional failure in the first Windows rerun; the latest native run remains
pending.

All five stripped binaries compile under Go 1.26.8 with OTEL SDK 1.45.0. The macOS ARM64
binary is 15,733,010 bytes, under the 16 MiB cap. The other targets shrink by 38.22% to
40.05% against stripped frozen-source binaries built with the same toolchain. Fresh 30-run
process comparisons before the OTEL SDK update on six corpora retained identical file evidence.
Raw results and binary digests for those process runs are in
`artifacts/bench/release-candidate-go1268-20260923/`.

| Workload | Median process speedup | Process p95 ratio | Peak RSS ratio |
|---|---:|---:|---:|
| Small files | 1.153x | 0.882x | 0.934x |
| Mixed heavy tail | 1.867x | 0.610x | 0.909x |
| Sensitive dense | 1.402x | 0.712x | 0.910x |
| Duplicate logs | 1.317x | 0.758x | 0.911x |
| Wide/deep | 1.142x | 0.803x | 0.923x |
| Bounded content | 2.015x | 0.563x | 0.888x |

The four core process-median speedups have a 1.412x geometric mean under this toolchain.
Process medians are a separate measure from the specified nine-sample Go benchmark throughput
gate. The updated binary still needs that gate on a paired controlled runner. The labeled
`Schema v3 release validation` workflow is prepared to run it on a fixed macOS ARM64 runner.

The first controlled run on this revision collected matching process evidence but its baseline
benchmark emitted millions of progress characters into the captured output. The benchmark
parser could not recover nine clean samples per workload, and this run is not valid speed-gate
evidence. Both benchmark and process harnesses now disable baseline progress display so the
next paired run measures scanning with equivalent non-interactive diagnostics.

## Validation and unresolved gates

`make lint`, `make test`, macOS scanner/output/config race tests, local `govulncheck`, and all
five cross-builds pass on the updated source. Native Linux ARM64 and macOS AMD64 tests passed
on the first PR revision; the updated revision and Windows fixes await CI validation.

Local OTLP/HTTP tests cover accepted export, outage and replay, privacy before spooling,
destination mismatch, partial success, permanent HTTP rejection, exclusive invocation lock,
corrupt committed batches, capacity refusal, and event identity. They do not substitute for
fault injection at every commit/acknowledgment cut point or a managed receiver pilot.

The following remain release blockers or unverified requirements:

- Reproduce at least 1.75x equivalent-work throughput on the updated Go 1.26.8 candidate and
  verify every workload's median and p95 limits on controlled paired runners. The 1.753x result
  belongs to the earlier Go 1.26.3 build.
- Complete controlled wide/deep and bounded-content throughput checks, controlled first-pass
  behavior, delivery overhead, and healthy/slow/disconnected receiver measurements.
- Rerun native Windows and macOS AMD64 tests on the updated revision, complete disk-full and
  crash-cutpoint tests, and run a 25–50 device
  disconnected-recovery pilot using existing deployment tooling.
- Verify the final candidate on controlled release runners. Hosted or local laptop timings are
  development evidence, not a release certificate.

Do not publish a general-availability release or call the collector fleet-ready until these
gates pass. A prerelease may be used for bounded validation with explicit limitations. Kai
ingestion and the management console remain separate milestones.
