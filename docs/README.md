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
IBANs, UK National Insurance numbers, EU VAT IDs, India Aadhaar numbers,
China resident IDs, and custom regex patterns. Scan only selected types with
`--include-sensitive-data-types` or skip some with `--exclude-sensitive-data-types`.
Safnari also reports system details such as
running processes. The goal of this documentation is to provide deeper
explanations and examples than the top level README.

## Building

Safnari is written in Go. Building from source requires a recent Go toolchain and GNU Make.

```sh
git clone https://github.com/ProvisioInsights/Safnari.git
cd Safnari
make build
```

The resulting binary is placed in the `bin` directory. To include runtime tracing, pass the `trace`
build tag:

```sh
cd src
go build -tags trace -o ../bin/safnari-trace ./cmd
```

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
- `--scan-processes`: Enable process scanning (default: `true`).
- `--format`: Output format: json or csv (default: `json`).
- `--output`: Output file name (default: `safnari-<timestamp>-<unix>.json`).
- `--concurrency`: Concurrency level (default: number of logical CPUs).
- `--nice`: Nice level: high, medium, or low (default: `medium`).
- `--hashes`: Comma-separated list of hash algorithms (default: `md5,sha1,sha256`).
- `--search`: Comma-separated list of search terms (default: none).
- `--include`: Comma-separated list of include patterns (default: none).
- `--exclude`: Comma-separated list of exclude patterns (default: none).
- `--max-file-size`: Maximum file size to process in bytes (default: `10485760`).
- `--max-output-file-size`: Maximum output file size before rotation in bytes
  (default: `104857600`).
- `--log-level`: Log level: debug, info, warn, error, fatal, or panic (default: `info`).
- `--max-io-per-second`: Maximum disk I/O operations per second (default: `1000`).
- `--config`: Path to JSON configuration file (default: none).
- `--extended-process-info`: Gather extended process information (requires
  elevated privileges) (default: `false`).
- `--include-sensitive-data-types`: Comma-separated list of sensitive data types
  to include when scanning. Use `all` to include all built-in patterns (default: none).
- `--exclude-sensitive-data-types`: Comma-separated list of sensitive data types
  to skip when scanning (default: none).
- `--custom-patterns`: Custom sensitive data patterns as name:regex pairs
  (default: none).
- `--fuzzy-hash`: Enable fuzzy hashing (ssdeep) (default: `false`).
- `--delta-scan`: Only scan files modified since the last run (default: `false`).
- `--last-scan-file`: Path to timestamp file for delta scans (default: `.safnari_last_scan`).
- `--last-scan`: Timestamp of last scan in RFC3339 format (e.g.,
  `2006-01-02T15:04:05Z`) (default: none).
- `--version`: Print version and exit.

See `./bin/safnari --help` for detailed usage information.

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
