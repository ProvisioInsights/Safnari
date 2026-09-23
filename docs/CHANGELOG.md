# Changelog

## Unreleased: schema-v3 collector

This is a breaking release. Update downstream consumers before replacing a schema-v2 binary.
See [migration-v3.md](migration-v3.md) for configuration, spool, and rollback steps.

### Added

- Schema-v3 scan and event identity, scan lifecycle records, and structured coverage outcomes.
- Private disk-backed OTLP/HTTP delivery with replay, bounded capacity, destination binding,
  and separate exit codes for pending and rejected export.
- Matching unstripped diagnostic builds for the five supported release targets.

### Changed

- SHA-256 is the default hash. MD5, SHA-1, BLAKE3, and TLSH remain explicit options.
- Delta scans default to mtime mode; chunk caching remains an explicit option.
- The streaming scan reuses file information and buffers, reads directories in bounded batches,
  and selects exact-search counting based on the term set and observed match density.
- Diagnostics use `log/slog` on stderr and progress uses periodic counters.
- The standard build uses stable JSON-v2 and retains OTEL/HTTP. The experimental build switch
  and alternate JSON encoder have been removed.
- Release builds require Go 1.27.1 with gRPC 1.83.2 and updated x/net and OTEL SDK dependencies.
- macOS release binaries require macOS 13 Ventura or later under Go 1.27.

### Fixed

- Windows service collection now opens service handles before querying status.
- The fallback file-open path rejects a file replaced after traversal.
- OTEL retries respect the receiver's `Retry-After` delay during an invocation.

### Removed

- PDF metadata extraction, inactive mmap read modes, redundant SIMD switches, and the
  alternative JSON build matrix. PDF files remain eligible for inventory, hashing, and content
  inspection, with an explicit unsupported-metadata indication where applicable.

### Validation status

The gRPC-patched Go 1.26.8 candidate measured a 2.473x four-workload warm-cache throughput gain
against source `956d509702b48fa967ae0e339ce16f648cf470d2` on a paired macOS ARM64 runner
at equivalent coverage. Its 90 paired process runs per workload passed the p95 and memory limits;
all five size targets passed. The earlier 30-run small-file p95 failure remains recorded in
[release-gates-v3.md](release-gates-v3.md). Crash-cutpoint, delivery-overhead, and managed-device
pilot requirements remain before general availability.

The Go 1.27.1 toolchain update passed local tests, race checks, cross-builds, size, and paired
warm-cache regression checks. Its four-workload throughput ratio against Go 1.26.8 was 0.982x;
the toolchain alone did not improve scan speed. The controlled runner measured a 3.146x
four-workload speedup against the frozen pre-optimization source on the exact Go 1.27.1 PR head.
Its process p95, memory, and five target-size gates passed. Native macOS, Linux ARM64, and Windows
PR tests passed. See [release-gates-v3.md](release-gates-v3.md) for the evidence boundary.
