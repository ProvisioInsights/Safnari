# Safnari: File and System Information Gatherer

Safnari is a versatile tool for gathering file and system information from a host
machine. It scans user-defined paths, collects rich metadata about files, and
retrieves system details such as running processes. Safnari supports numerous
configuration flags for filtering, hashing, and output control.

## Features

- Gather host information such as OS details, installed patches, and hostname
- List running processes and their details (PID, name, memory usage, etc.)
- Scan files across specified paths or all drives
- Calculate file hashes (MD5, SHA1, SHA256)
- Extract metadata from images (EXIF), PDFs, and DOCX documents
- Detect sensitive data patterns such as emails, credit cards (with Luhn validation), AWS keys, JWT
  tokens, street addresses, IBANs, UK National Insurance numbers, EU VAT IDs, India Aadhaar numbers,
  China resident IDs, and user-defined regexes via the `--custom-patterns` JSON flag. Users can scan
  only selected types with `--include-sensitive-data-types` or skip some with
  `--exclude-sensitive-data-types`.
- Search for arbitrary terms with `--search` (matches are reported as `search_hits` in the output).
- Redact sensitive matches in output with `--redact-sensitive` (mask or hash).
- Toggle system information gathering, file metadata scanning, sensitive data detection, and
  process enumeration independently via CLI flags
- Output results with metrics in JSON or CSV format

## Installation

### Build from Source

```sh
git clone https://github.com/ProvisioInsights/Safnari.git
cd Safnari
make build
```

The compiled binary will be located in the `bin` directory.

Safnari enables the experimental JSON v2 encoder by default for better throughput. To disable it,
set `JSONV2=0` when building or testing.

Safnari embeds its version at build time. To set the version string, pass a
`-ldflags` option:

```sh
cd src
go build -ldflags "-X safnari/version.Version=v1.0.2" -o ../bin/safnari ./cmd
```

To cross-compile for other platforms, set `GOOS` and `GOARCH`:

```sh
# macOS Apple Silicon
GOOS=darwin GOARCH=arm64 make build

# Linux ARM64
GOOS=linux GOARCH=arm64 make build
```

You can build binaries for all supported targets at once with:

```sh
make build-all
```

To include runtime tracing for debugging and performance analysis, build with
the `trace` tag:

```sh
cd src
go build -tags trace -o ../bin/safnari-trace ./cmd
```

Trace-enabled builds record code-level tasks and regions to `trace.out`. Use
`go tool trace trace.out` to inspect execution timing and behavior.

For low-overhead tracing in any build, enable the in-memory flight recorder with
`--trace-flight`. Safnari will dump the recent trace window to `trace-flight.out`
at exit or on interrupt. Use `--trace-flight-max-bytes` and `--trace-flight-min-age`
to tune the capture window.

### Download Pre-Compiled Binary

Check the [releases page](https://github.com/ProvisioInsights/Safnari/releases) for
binaries for your operating system. Releases use the `safnari-<date><letter>` naming
scheme, where `date` is in `YYYYMMDD` format and `letter` increments if multiple releases
occur on the same day.

## Usage

Run the binary with `-h` to see all available options. By default Safnari scans
the current working directory using a concurrency level equal to the number of
logical CPUs. It does not search for any strings or sensitive data types unless
explicitly requested and writes results to a timestamped file named
`safnari-<human-readable>-<unix>.json`.

If only `--exclude-sensitive-data-types` is supplied, Safnari scans all built-in patterns except
those excluded. When both include and exclude lists are provided, the exclusion list removes types
from the inclusion list. Custom regex patterns can be added with `--custom-patterns` using a JSON
object mapping names to regexes.

### Default flags

Running Safnari without any flags applies these defaults:

- `--path`: `.`
- `--all-drives`: `false`
- `--scan-files`: `true`
- `--scan-sensitive`: `true`
- `--scan-processes`: `true`
- `--collect-system-info`: `true`
- `--format`: `json`
- `--output`: `safnari-<timestamp>-<unix>.json`
- `--concurrency`: number of logical CPUs (effective value adjusted by `--nice` unless
  `--concurrency` is set)
- `--nice`: `medium`
- `--hashes`: `md5,sha1,sha256`
- `--search`: none
- `--include`: none
- `--exclude`: none
- `--max-file-size`: `10485760`
- `--max-output-file-size`: `104857600`
- `--log-level`: `info`
- `--max-io-per-second`: `1000` (set to `0` to disable throttling)
- `--config`: none
- `--extended-process-info`: `false`
- `--include-sensitive-data-types`: none
- `--exclude-sensitive-data-types`: none
- `--fuzzy-hash`: `false`
- `--fuzzy-algorithms`: none (defaults to `tlsh` when fuzzy hashing enabled)
- `--fuzzy-min-size`: `256`
- `--fuzzy-max-size`: `20971520`
- `--delta-scan`: `false`
- `--last-scan-file`: `.safnari_last_scan`
- `--last-scan`: none
- `--skip-count`: `false`
- `--redact-sensitive`: `mask` (use `none` to disable)
- `--collect-xattrs`: `true`
- `--xattr-max-value-size`: `1024`
- `--collect-acl`: `true`
- `--collect-scheduled-tasks`: `true`
- `--collect-users`: `true`
- `--collect-groups`: `true`
- `--collect-admins`: `true`
- `--scan-ads`: `false`
- `--auto-tune`: `true`
- `--auto-tune-interval`: `5s`
- `--auto-tune-target-cpu`: `60`
- `--otel-endpoint`: none (enable OTLP/HTTP log export)
- `--otel-headers`: none
- `--otel-service-name`: `safnari`
- `--otel-timeout`: `5s`
- `--trace-flight`: `false`
- `--trace-flight-file`: `trace-flight.out`
- `--trace-flight-max-bytes`: `0`
- `--trace-flight-min-age`: `0`

```sh
./bin/safnari-$(go env GOOS)-$(go env GOARCH) --path /home/user --hashes sha256 --search "password"
```

This will scan `/home/user`, compute SHA-256 hashes, search for the term
`password`, and write results to a file such as
`safnari-20240130-150405-1706625005.json` unless an alternate output filename
is provided.

Search results are included as a `search_hits` map where each term maps to the number of matches
found in that file.

When `--format csv` is selected, Safnari writes a single CSV with a `record_type` column. The file
starts with `system_info` and `process` rows, followed by `file` rows, and finishes with a
`metrics` row. Complex fields such as hashes, metadata, sensitive data, and search hits are stored
as JSON-encoded strings in their respective columns. All outputs include a `schema_version` field
to support forward compatibility.

Metrics include start/end timestamps, total files discovered, files scanned, files written to the
output, and total running processes.

Use `--version` to print the embedded version. On startup Safnari checks the
latest GitHub release and logs a message if an update, including any noted
security fixes, is available.

### OTEL Export

When `--otel-endpoint` is set (or OTEL environment variables are present), Safnari exports records over OTLP/HTTP Logs. The exported log body contains the same fields as the local JSON records, and each log includes `record_type` and `schema_version` attributes for reconstruction.

## Security Posture (Brief)

Safnari is a local CLI with no server listener. The primary security risks are the sensitivity of scan outputs and the integrity of any future telemetry exports. Output files are created with `0600` permissions by default, and sensitive matches are masked unless explicitly disabled. For managed fleet or OTEL deployments, prefer authenticated and encrypted export channels with data-minimization defaults (hashes/locators over raw values).

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

## Documentation

See the [docs](docs/README.md) directory for extended guides and additional examples.

## Development

Before submitting changes, format the Go source and run the linters and tests:

```sh
make fmt
make lint
make test
```

## Contributing

Contributions to Safnari are always welcome! Feel free to open issues or submit
pull requests to help improve the project.

## License

Safnari is released under the [MIT License](LICENSE).
