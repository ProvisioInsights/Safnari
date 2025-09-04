# Safnari: File and System Information Gatherer

Safnari is a versatile tool for gathering file and system information from a host machine. It scans user-defined paths, collects rich metadata about files, and retrieves system details such as running processes. Safnari supports numerous configuration flags for filtering, hashing, and output control.

## Features

- Gather host information such as OS details, installed patches, and hostname
- List running processes and their details (PID, name, memory usage, etc.)
- Scan files across specified paths or all drives
- Calculate file hashes (MD5, SHA1, SHA256)
- Extract metadata from images (EXIF), PDFs, and DOCX documents
- Detect sensitive data patterns such as emails and credit cards
- Output results with metrics in JSON format

## Installation

### Build from Source

```sh
git clone https://github.com/Forgence/Safnari.git
cd Safnari
make build
```

The compiled binary will be located in the `bin` directory.

### Download Pre-Compiled Binary

Check the [releases page](https://github.com/Forgence/Safnari/releases) for binaries for your operating system.

## Usage

Run the binary with `--help` to see all available options. Example:

```sh
./bin/safnari-$(go env GOOS)-$(go env GOARCH) --path /home/user --hashes sha256 --search "password"
```

This will scan `/home/user`, compute SHA-256 hashes, search for the term "password," and write results to `output.json` by default.

## Contributing

Contributions to Safnari are always welcome! Feel free to open issues or submit pull requests to help improve the project.

## License

Safnari is released under the [MIT License](LICENSE).
