# Migrating to Safnari schema v3

This release changes local NDJSON and OTLP log records. Update consumers before replacing v2
binaries. A scan still uses the same invocation syntax; managed export is enabled only when an
OTLP endpoint is configured.

## Changed defaults and removed features

- `--hashes` defaults to `sha256`. Pass `--hashes md5,sha1,sha256` if a v2 consumer still
  requires the earlier hash set. BLAKE3 and TLSH remain explicit options.
- `--delta-cache-mode` defaults to `mtime` when `--delta-scan` is used. Pass
  `--delta-cache-mode chunk` to opt in to chunk caching.
- PDF metadata extraction is removed. A PDF file remains in file inventory and may still be
  hashed and content-scanned; metadata collection records `pdf_metadata_unsupported` where
  PDF metadata would previously have been attempted.
- `--content-read-mode` and `--mmap-min-size` are removed because the mmap reader was not on
  the active streaming path. Remove these keys from JSON configuration too.
- `--simd-fastpath` is removed. Its wrappers did not select a distinct production algorithm.
- `--perf-profile ultra` no longer disables detection. Set explicit coverage limits to change
  sampling or truncation. Diagnostics are written to stderr and progress uses periodic counts.

## Schema and identity

Every local record is an NDJSON envelope with `schema_version: "3"`, `record_type`, `payload`,
`device_id`, `scan_id`, `sequence`, `event_id`, `observed_at`, `scanner_version`, and
`policy_digest`. The event ID is derived from device ID, scan ID, and sequence and is stable
across export retries. A private installation ID is generated on first use unless `--device-id`
is supplied. These IDs correlate events; they do not authenticate a device.

`scan_start` and `scan_complete` bracket each invocation. A completed scan only means local
collection finished. It does not mean the receiver accepted every export batch. `metrics`
continues to report file counts. Consumers should accept records in any traversal order and
deduplicate exported events by `event_id`.

## Managed OTLP delivery

Set `--otel-endpoint` to an authenticated OTLP/HTTP logs receiver. Use `--otel-headers` or
standard OTEL header environment variables to supply credentials externally. HTTPS is required
except for loopback development. The spool defaults to a private `safnari/spool` directory in
the user cache, or can be set with `--spool-dir`. Keep this directory on persistent storage and
exclude it from backup ingestion and scan roots. Safnari itself excludes its spool from scans.
When `--otel-from-env` is enabled, `OTEL_EXPORTER_OTLP_ENDPOINT` is treated as a base URL and
`/v1/logs` is appended; `OTEL_EXPORTER_OTLP_LOGS_ENDPOINT` is used as the complete logs URL.

Records are sanitized before entering the spool. Default export includes detector identifiers,
counts, and coverage signals but excludes raw matches, search terms, paths, filenames, command
lines, and detailed metadata. Explicit OTEL export flags permit additional fields. Review those
flags before enabling them for a managed fleet.

A batch is committed at 512 records, 1 MiB, or 250 ms. The spool capacity is 1 GiB. Pending
committed batches are retained through retryable receiver outages and replayed on the next
invocation or with `--replay-only`. Uncommitted buffered records can be lost on abrupt process
termination. A changed endpoint or credential header identity will not silently receive old
batches: drain the old spool with its original configuration, or select a new state directory.
The receiver may accept a batch more than once after a lost acknowledgment, so downstream
consumers must deduplicate by event ID. Acceptance does not prove downstream indexing.

Partial-success and permanent-rejection responses create a retained failed batch and failure
receipt; they are not retried automatically. Investigate and resolve them before reuse. Safnari
does not evict unacknowledged batches automatically. If the spool fills or disk writes fail,
the scan exits incomplete and the operator must restore storage or drain delivery.

Exit codes are `0` for successful scan and delivery, `1` for scan/configuration/persistence
failure, `2` for pending delivery, and `3` for terminal export rejection. A scan can be locally
complete and return `2` or `3` because export completion is separate.

## Rollback

Keep the preceding binary and its state directory separate. A v2 binary must not be pointed at
a v3 spool. Preserve the v3 spool for replay by a compatible v3 binary after rollback. Do not
delete pending or failed batches as part of binary rollback.

General-availability publication remains gated on the validation in
[release-gates-v3.md](release-gates-v3.md). A prerelease can support a bounded pilot; CI retains
build artifacts and unstripped diagnostic binaries for validation.
