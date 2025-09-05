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
- Detect sensitive data patterns such as emails, credit cards (with Luhn validation), AWS keys, JWT tokens, street addresses, IBANs, UK National Insurance numbers, EU VAT IDs, India Aadhaar numbers, China resident IDs, and user-defined regexes. Patterns can be enabled or disabled individually.
- Output results with metrics in JSON format

## Installation

### Build from Source

```sh
git clone https://github.com/ProvisioInsights/Safnari.git
cd Safnari
make build
```

The compiled binary will be located in the `bin` directory.

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

### Download Pre-Compiled Binary

Check the [releases page](https://github.com/ProvisioInsights/Safnari/releases) for
binaries for your operating system.

## Usage

Run the binary with `-h` to see all available options. By default Safnari scans
the current working directory using a concurrency level equal to the number of
logical CPUs. It does not search for any strings or sensitive data types unless
explicitly requested and writes results to a timestamped file named
`safnari-<human-readable>-<unix>.json`.

### Default flags

Running Safnari without any flags applies these defaults:

- `--path`: `.`
- `--all-drives`: `false`
- `--scan-files`: `true`
- `--scan-processes`: `true`
- `--format`: `json`
- `--output`: `safnari-<timestamp>-<unix>.json`
- `--concurrency`: number of logical CPUs
- `--nice`: `medium`
- `--hashes`: `md5,sha1,sha256`
- `--search`: none
- `--include`: none
- `--exclude`: none
- `--max-file-size`: `10485760`
- `--max-output-file-size`: `104857600`
- `--log-level`: `info`
- `--max-io-per-second`: `1000`
- `--config`: none
- `--extended-process-info`: `false`
- `--sensitive-data-types`: none
- `--exclude-sensitive-data-types`: none
- `--fuzzy-hash`: `false`
- `--delta-scan`: `false`
- `--last-scan-file`: `.safnari_last_scan`
- `--last-scan`: none
- `--skip-count`: `false`

```sh
./bin/safnari-$(go env GOOS)-$(go env GOARCH) --path /home/user --hashes sha256 --search "password"
```

This will scan `/home/user`, compute SHA-256 hashes, search for the term
`password`, and write results to a file such as
`safnari-20240130-150405-1706625005.json` unless an alternate output filename
is provided.

Use `--version` to print the embedded version. On startup Safnari checks the
latest GitHub release and logs a message if an update, including any noted
security fixes, is available.

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
