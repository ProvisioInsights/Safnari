# Performance Architecture

Safnari now uses a shared streaming scan path instead of reopening the same file
for each content-oriented module. The goal of this design is straightforward:
pay the open cost once, stream bytes once, and let specialized consumers perform
hashing, search, sensitive matching, fuzzy hashing, and metadata extraction
without materializing the same payload repeatedly.

## Runtime Architecture

The current scanner fast path is built from five internal pieces:

- `ChunkSource` owns a single file descriptor, header sample, MIME verdict,
  likely-text verdict, and reusable chunk iterator.
- `ScanPipeline` fans one forward-only stream into `ChunkConsumer`
  implementations for hashes, search, sensitive matching, and fuzzy hashing.
- `streamAhoMatcher` replaces the previous streamed exact-search loop with a
  multi-pattern automaton that counts all search terms in one pass.
- `SizeLaneScheduler` classifies work as `small`, `medium`, `large`, or
  `expensive` so tiny files are not pinned behind whale files.
- `output.Writer` now uses a bounded producer queue and a dedicated writer
  goroutine instead of serializing all callers on one mutex in the hot path.

Delta scans also have a `DeltaChunkCache`. It stores BLAKE3 chunk fingerprints
and cached search, sensitive, and fuzzy analysis behind a Binary Fuse filter so
negative lookups stay cheap. Full-file evidence hashes are still recomputed.

## Benchmark Methodology

The current measurements come from these artifacts:

- Baseline artifact: `artifacts/bench/20260306-150131`
- Candidate artifact: `artifacts/bench/20260306-155118`
- Expanded baseline corpus samples: a temporary worktree at commit `39a0410`
  using the current benchmark definitions
- Targeted delta-cache-mode samples:
  `artifacts/bench/manual/delta-cache-modes.txt`
- Targeted `BenchmarkCollectFileData` samples:
  `artifacts/bench/manual/collect-file-data-candidate.txt`

The original baseline artifact predates the expanded corpus suite, so the
`small_files`, `mixed_heavy_tail`, `duplicate_logs`, and `delta_second_run`
"before" numbers were captured by running the current benchmark definitions
against the pre-overhaul commit in a detached worktree. That keeps the code
comparison honest even though the original suite was smaller.

All p50 durations below use ultra-profile medians. Lower is better. The
before/after table reflects the last full artifact comparison before the final
duplicate-log and delta regression pass landed.

Current CI behavior is intentionally split:

- pull requests run `benchmark-pr`, which captures the same benchmark artifacts
  and a gate summary but treats the current threshold miss set as
  informational;
- pushes to `main` and tags keep strict non-PR benchmark enforcement in
  `benchmark-matrix`.

## Before And After

| Benchmark | Before p50 (ms) | After p50 (ms) | Delta |
| --- | --- | --- | --- |
| Synthetic tree | `54.62` | `33.41` | `1.63x faster` |
| Sensitive dense | `39.13` | `34.08` | `1.15x faster` |
| Small files | `231.73` | `178.66` | `1.30x faster` |
| Mixed heavy tail | `271.82` | `197.39` | `1.38x faster` |
| Duplicate logs | `20.79` | `71.92` | `0.29x` |
| Delta second run | `1167.15` | `1302.33` | `0.90x` |

Three workload classes improved materially:

- Synthetic inventory is down about `38.8%`.
- Small-file fanout is down about `22.9%`.
- Mixed heavy-tail trees are down about `27.4%`.

The duplicate-log and delta-second-run workloads still regress relative to the
pre-overhaul baseline in that artifact comparison. The scanner refactor is in
place, but those paths needed a follow-up tuning pass.

## Targeted Follow-up Reruns

After the final regression work in this branch, the duplicate-log and delta
second-run corpora were rerun directly on March 6, 2026 with:

```sh
cd src
SAFNARI_DISABLE_PROGRESS=1 go test -run '^$' -bench '^BenchmarkScanFilesCorpora/duplicate_logs/(adaptive|ultra)$' -benchmem -count=3 ./scanner
SAFNARI_DISABLE_PROGRESS=1 go test -run '^$' -bench '^BenchmarkDeltaSecondRunCorpora/duplicate_logs/(mtime|chunk|adaptive|ultra)$' -benchmem -count=3 ./scanner
```

Those focused reruns show:

- Duplicate-log p50 under `ultra` is now about `111.98 ms/op`, still slower
  than the pre-overhaul baseline, but with the repeated-match hot path cut down
  to roughly `6.6-6.9 MB/op` and about `87k allocs/op`.
- Delta second-run p50 is about `1317.86 ms/op` for `mtime` and
  `1433.30 ms/op` for `chunk` on the duplicate-log corpus.
- The important delta improvement is memory shape: chunk mode no longer blows up
  into the earlier cache-heavy `130 MB+` / `267k+ allocs` class on this corpus.
  Small changed files that still require authoritative full-file hashes now
  bypass chunk-cache bookkeeping automatically, so chunk mode falls back toward
  mtime-like resource use when the cache is unlikely to pay back.

The duplicate-log and sensitive-dense benchmark corpora intentionally contain
fixture tokens that look like JWTs and other secrets so the scanner exercises
its sensitive-data paths under load. The benchmark source marks those literals
with `gitleaks:allow` comments so repository secret scanning can stay strict
without treating the synthetic fixtures as real leaks.

## Memory And Microbenchmarks

End-to-end synthetic memory metrics from the benchmark reports:

| Metric | Before | After | Delta |
| --- | --- | --- | --- |
| Synthetic bytes/op | `116949723` | `18810979` | `-83.9%` |
| Synthetic allocs/op | `85322` | `100705` | `+18.0%` |
| Peak RSS (KB) | `342507520` | `347930624` | `+1.6%` |

Two targeted microbenchmarks are worth calling out:

- `BenchmarkCollectFileData/reuse-prebuilt-modules` improved from
  `64.4 us` to `22.4 us`, and bytes/op dropped from roughly `268 KB` to
  roughly `5.7 KB`.
- That same microbenchmark did not hit the allocation goal. Median allocs/op
  moved from `39` to `52`, so the planned allocation-reduction gate is still
  open work.

The artifact-era delta cache mode benchmark showed that the architecture was
implemented but not yet paying for itself on the original duplicate-log corpus:

| Delta second run mode | p50 (ms) |
| --- | --- |
| `mtime` | `1229.88` |
| `chunk` | `1285.98` |

On that artifact snapshot the chunk cache was about `0.96x` the speed of the
mtime path. The latest focused reruns are still not a net win on wall clock for
this corpus, but they no longer carry the earlier cache-payload memory penalty.

## Current Interpretation

The one-open pipeline, shared streaming consumers, scheduler, and async writer
are all implemented and measurably helping the general scan path. The overhaul
already cut the dominant synthetic path substantially and reduced bytes/op
dramatically.

The remaining weak spots are specific:

- duplicate-log scans are slower than the old code,
- chunk-cache delta scans are closer to mtime on the duplicate-log corpus but
  still not beating it on wall clock,
- and allocation-count reduction has not caught up with the large bytes/op win.

Those are now isolated tuning problems instead of architectural unknowns.

## Gate Status

The new artifact-compare gate was exercised against:

- baseline: `artifacts/bench/manual-baseline-compare-20260306`
- candidate: `artifacts/bench/manual-candidate-compare-20260306`

It currently passes:

- synthetic adaptive speedup,
- small-files adaptive speedup,
- mixed-heavy-tail adaptive speedup,
- peak RSS ratio.

It currently fails:

- sensitive adaptive speedup,
- `BenchmarkCollectFileData` allocation reduction,
- delta chunk-versus-mtime speedup.

That means the strict gate remains useful for non-PR benchmark enforcement and
release tracking, but the pull-request benchmark job currently serves as a
reporting lane until those thresholds are brought fully back into line.
