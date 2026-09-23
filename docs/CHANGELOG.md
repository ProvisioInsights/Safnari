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
- The standard build uses JSON-v2 and retains OTEL/HTTP.

### Removed

- PDF metadata extraction, inactive mmap read modes, redundant SIMD switches, and the
  alternative JSON build matrix. PDF files remain eligible for inventory, hashing, and content
  inspection, with an explicit unsupported-metadata indication where applicable.

### Validation status

The measured four-workload local warm-cache throughput gain is 1.753x against source
`956d509702b48fa967ae0e339ce16f648cf470d2`, at equivalent configured coverage. The
accepted aggregate speed target is 1.75x. This local result is not controlled-runner proof.
The remaining release requirements are tracked in [release-gates-v3.md](release-gates-v3.md).
