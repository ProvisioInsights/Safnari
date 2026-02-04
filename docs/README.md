# Safnari Documentation

This directory contains extended documentation for Safnari.

## Contents

- [Overview](#overview)
- [Building](#building)
- [Usage](#usage)
- [Configuration](#configuration)
- [Examples](#examples)

## Overview

Safnari collects file metadata and system information from user specified paths. It can hash files,
search for sensitive strings such as emails, credit cards, AWS keys, JWT tokens, street addresses,
IBANs, UK National Insurance numbers, EU VAT IDs, India Aadhaar numbers, China resident IDs, and
custom regex patterns supplied via the `--custom-patterns` JSON flag. Scan only selected types with
`--include-sensitive-data-types` or skip some with `--exclude-sensitive-data-types`. Use `--search`
to scan for arbitrary terms (hits are reported as `search_hits` in output). Safnari also reports
system details such as running processes. File metadata collection, system information gathering,
process enumeration, and sensitive data scanning can be enabled independently. The goal of this
documentation is to provide deeper explanations and examples than the top level README.

## Building

Safnari is written in Go. Building from source requires a recent Go toolchain and GNU Make.

```sh
git clone https://github.com/ProvisioInsights/Safnari.git
cd Safnari
make build
```

The resulting binary is placed in the `bin` directory. Safnari enables the experimental JSON v2
encoder by default for better throughput. To disable it, set `JSONV2=0` when building or testing.

To include runtime tracing, pass the `trace` build tag:

```sh
cd src
go build -tags trace -o ../bin/safnari-trace ./cmd
```

For low-overhead tracing in any build, enable the in-memory flight recorder with
`--trace-flight`. Safnari will dump the recent trace window to `trace-flight.out`
at exit or on interrupt. Use `--trace-flight-max-bytes` and `--trace-flight-min-age`
to tune the capture window.

To embed a version string during compilation, use an `-ldflags` parameter:

```sh
cd src
go build -ldflags "-X safnari/version.Version=v1.0.2" -o ../bin/safnari ./cmd
```

## Development

Format, lint, and test the codebase before submitting patches:

```sh
make fmt
make lint
make test
```

## Usage

Run the compiled binary with desired flags. Running with `-h` prints all options.

```sh
./bin/safnari-$(go env GOOS)-$(go env GOARCH) --help
```

Use `--version` to display the current version. On startup Safnari checks the latest
GitHub release and logs a message if a newer version, including any security fixes,
is available.

## Configuration

Safnari accepts the following flags. Each description lists the default value in parentheses:

- `--path`: Comma-separated list of start paths to scan (default: `.`).
- `--all-drives`: Scan all local drives (Windows only) (default: `false`).
- `--scan-files`: Enable file scanning (default: `true`).
- `--scan-sensitive`: Enable sensitive data scanning (default: `true`).
- `--scan-processes`: Enable process scanning (default: `true`).
- `--collect-system-info`: Collect system information (default: `true`).
- `--format`: Output format: json or csv (default: `json`).
- `--output`: Output file name (default: `safnari-<timestamp>-<unix>.json`).
- `--concurrency`: Concurrency level (default: number of logical CPUs; effective value is adjusted
  by `--nice` unless `--concurrency` is set).
- `--nice`: Nice level: high, medium, or low (default: `medium`).
- `--hashes`: Comma-separated list of hash algorithms (default: `md5,sha1,sha256`).
- `--search`: Comma-separated list of search terms (default: none).
- `--redact-sensitive`: Redact sensitive matches in output: mask or hash (default: `mask`). Use `none` to disable.
- `--include`: Comma-separated list of include patterns (default: none).
- `--exclude`: Comma-separated list of exclude patterns (default: none).
- `--max-file-size`: Maximum file size to process in bytes (default: `10485760`).
- `--max-output-file-size`: Maximum output file size before rotation in bytes
  (default: `104857600`).
- `--log-level`: Log level: debug, info, warn, error, fatal, or panic (default: `info`).
- `--max-io-per-second`: Maximum disk I/O operations per second (default: `1000`).
  Use `0` to disable throttling.
- `--config`: Path to JSON configuration file (default: none).
- `--extended-process-info`: Gather extended process information (requires
  elevated privileges) (default: `false`).
- `--include-sensitive-data-types`: Comma-separated list of sensitive data types
  to include when scanning. Use `all` to include all built-in patterns (default: none).
- `--exclude-sensitive-data-types`: Comma-separated list of sensitive data types
  to skip when scanning (default: none).
- `--custom-patterns`: Custom sensitive data patterns as a JSON object mapping
  names to regexes (default: none).
- `--fuzzy-hash`: Enable fuzzy hashing (TLSH) (default: `false`).
- `--fuzzy-algorithms`: Comma-separated list of fuzzy hash algorithms (default: `tlsh` when fuzzy hashing enabled).
- `--fuzzy-min-size`: Minimum file size in bytes for fuzzy hashing (default: `256`).
- `--fuzzy-max-size`: Maximum file size in bytes for fuzzy hashing (default: `20971520`).
- `--delta-scan`: Only scan files modified since the last run (default: `false`).
- `--last-scan-file`: Path to timestamp file for delta scans (default: `.safnari_last_scan`).
- `--last-scan`: Timestamp of last scan in RFC3339 format (e.g.,
  `2006-01-02T15:04:05Z`) (default: none).
- `--skip-count`: Skip initial file counting to start scanning immediately (default: `false`).
- `--collect-xattrs`: Collect extended attributes (default: `true`).
- `--xattr-max-value-size`: Max bytes of xattr values to capture (default: `1024`).
- `--collect-acl`: Collect ACLs (default: `true`).
- `--collect-scheduled-tasks`: Collect scheduled tasks (default: `true`).
- `--collect-users`: Collect local users (default: `true`).
- `--collect-groups`: Collect local groups (default: `true`).
- `--collect-admins`: Collect admin users/groups (default: `true`).
- `--scan-ads`: Scan Windows alternate data streams (default: `false`).
- `--auto-tune`: Auto-tune resource usage (default: `true`).
- `--auto-tune-interval`: Auto-tune interval (default: `5s`).
- `--auto-tune-target-cpu`: Auto-tune target CPU percent (default: `60`).
- `--otel-endpoint`: OTLP/HTTP logs endpoint (default: none).
- `--otel-headers`: Comma-separated OTEL headers (default: none).
- `--otel-service-name`: OTEL service name (default: `safnari`).
- `--otel-timeout`: OTEL export timeout (default: `5s`).
- `--trace-flight`: Enable flight recorder tracing (default: `false`).
- `--trace-flight-file`: Flight recorder output file (default: `trace-flight.out`).
- `--trace-flight-max-bytes`: Max bytes for flight recorder buffer (default: `0`).
- `--trace-flight-min-age`: Minimum age of trace events to retain (default: `0`).
- `--version`: Print version and exit.

If only `--exclude-sensitive-data-types` is provided, Safnari scans all built-in
patterns except those excluded. When both include and exclude flags are set, the
exclusion list removes types from the inclusion list.

When `--format csv` is selected, Safnari writes a single CSV file with a `record_type`
column. The file starts with `system_info` and `process` rows, followed by `file` rows,
and finishes with a `metrics` row. Complex fields such as hashes, metadata, sensitive
data, and search hits are stored as JSON-encoded strings in their respective columns.
All outputs include a `schema_version` field to support forward compatibility.

Metrics include start/end timestamps, total files discovered, files scanned, files written to the
output, and total running processes.

See `./bin/safnari --help` for detailed usage information.

## OTEL Export

When `--otel-endpoint` is set (or OTEL environment variables are present), Safnari exports records over OTLP/HTTP Logs. The exported log body contains the same fields as the local JSON records, and each log includes `record_type` and `schema_version` attributes for reconstruction.

## Capability Matrix

The table below summarizes what Safnari collects by default across platforms. Optional features can be disabled with the listed flags.

| Capability | macOS | Linux | Windows | Request / Flag | Privilege |
| --- | --- | --- | --- | --- | --- |
| Baseline file inventory | Yes | Yes | Yes | `--scan-files` | User |
| Cryptographic hashes (MD5/SHA1/SHA256) | Yes | Yes | Yes | `--hashes` | User |
| Fuzzy hashing (TLSH) | Yes | Yes | Yes | `--fuzzy-hash`, `--fuzzy-algorithms`, size limits | User |
| File metadata (EXIF/PDF) | Yes | Yes | Yes | `--scan-files` | User |
| File times (create/access/change) | Yes | Yes | Yes | `--scan-files` | User |
| File ID (inode/volume+file index) | Yes | Yes | Yes | `--scan-files` | User |
| Extended attributes (xattrs) | Yes | Yes | No | `--collect-xattrs`, `--xattr-max-value-size` | User |
| ACLs | No | No | Yes | `--collect-acl` | Admin for protected paths |
| Alternate Data Streams | No | No | Yes | `--scan-ads` | Admin for protected paths |
| Sensitive data scan | Yes | Yes | Yes | `--scan-sensitive`, include/exclude/custom patterns | User |
| Search terms | Yes | Yes | Yes | `--search` | User |
| Running processes | Yes | Yes | Yes | `--scan-processes`, `--extended-process-info` | Admin for full detail |
| System info (OS, patches, apps, startup, services) | Yes | Yes | Yes | `--collect-system-info` | User (some sources may need Admin) |
| Users / Groups / Admins | Yes | Yes | Yes | `--collect-users`, `--collect-groups`, `--collect-admins` | User (Admin for full detail) |
| Scheduled tasks | Yes | Yes | Yes | `--collect-scheduled-tasks` | User (Admin for system-wide) |
| Network interfaces | Yes | Yes | Yes | `--collect-system-info` | User |
| Open connections | Yes | Yes | Yes | `--collect-system-info` | Admin for full detail |
| Auto-tuning (CPU/I/O) | Yes | Yes | Yes | `--auto-tune`, `--auto-tune-interval`, `--auto-tune-target-cpu` | User |

## Examples

Scan a home directory, compute SHA-256 hashes, and search for a password string:

```sh
./bin/safnari --path /home/user --hashes sha256 --search password
```

Limit concurrency and write results to a custom file:

```sh
./bin/safnari --path /var/log --concurrency 4 --output logs.json
```

Additional guides and examples will be added here over time.
