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
search for sensitive strings, and report system details such as running processes. The goal of this
documentation is to provide deeper explanations and examples than the top level README.

## Building

Safnari is written in Go. Building from source requires a recent Go toolchain and GNU Make.

```sh
git clone https://github.com/Forgence/Safnari.git
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

## Usage

Run the compiled binary with desired flags. Running with `-h` prints all options.

```sh
./bin/safnari-$(go env GOOS)-$(go env GOARCH) --help
```

Use `--version` to display the current version. On startup Safnari checks the latest
GitHub release and logs a message if a newer version, including any security fixes,
is available.

## Configuration

Common flags include:

- `--path`: Comma separated list of paths to scan. Defaults to the current directory.
- `--hashes`: Comma separated list of hash algorithms to compute.
- `--search`: Search string or regular expression to look for in file contents.
- `--output`: Output filename. Defaults to a timestamped JSON file.
- `--concurrency`: Number of worker goroutines. Defaults to the number of logical CPUs.

See `./bin/safnari --help` for a complete list of flags.

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
