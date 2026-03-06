# Safnari Benchmark Report

- Date (UTC): `<timestamp>`
- Commit: `<commit>`
- Profile: `<profile-name>`

## Synthetic Tree

- p50 duration (ms): `<synthetic_p50_ms>`
- p95 duration (ms): `<synthetic_p95_ms>`
- bytes/op: `<synthetic_bytes_per_op>`
- allocs/op: `<synthetic_allocs_per_op>`
- peak RSS (KB): `<peak_rss_kb>`

## Corpus Medians (ms)

- sensitive_dense: `<sensitive_dense_p50_ms>`
- small_files: `<small_files_p50_ms>`
- mixed_heavy_tail: `<mixed_heavy_tail_p50_ms>`
- duplicate_logs: `<duplicate_logs_p50_ms>`
- delta_second_run: `<delta_second_run_p50_ms>`

## Notes

- Corpus: synthetic tree plus small-files, mixed, mixed-heavy-tail, sensitive-dense,
  duplicate-logs, large-file, and delta second-run benchmark corpora.
- Command: `make bench-ultra`.
