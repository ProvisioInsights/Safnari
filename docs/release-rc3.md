# Safnari schema v3 RC3

This prerelease packages the schema-v3 collector with Go 1.27.1, stable JSON-v2 encoding, and
durable OTLP/HTTP delivery. It includes the five stripped platform binaries, checksums, and
source and binary SBOMs. Matching unstripped diagnostic binaries are retained in the CI build.

Schema v3 changes local and exported records. Read the
[migration guide](https://github.com/ProvisioInsights/Safnari/blob/safnari-20260923a-rc3/docs/migration-v3.md)
before replacing a schema-v2 installation, and preserve any v3 spool when rolling back.

## Measured performance

The controlled macOS ARM64, warm-cache, scan-only comparison against frozen source
`956d509702b48fa967ae0e339ce16f648cf470d2` measured a **2.406× geometric-mean
throughput gain** at equivalent coverage. The four workload gains were 2.289× for small files,
2.156× for mixed heavy-tail files, 1.823× for sensitive-dense text, and 3.724× for duplicate
logs. Process p95 and peak RSS passed the release limits. All five stripped targets were at
least 38% smaller; macOS ARM64 measured 15,796,290 bytes. The Go 1.27.1 toolchain change alone
measured 0.982× throughput relative to Go 1.26.8.
An earlier controlled run on the same scanner code measured 3.146× and remains in the
repository; the charts show the newer RC3 PR run.
The [exact tag validation](https://github.com/ProvisioInsights/Safnari/actions/runs/35882734911)
passed at 2.394× geometric-mean throughput, with retained evidence, p95 latency, RSS, and all
five stripped size gates passing.

See the [throughput chart](https://github.com/ProvisioInsights/Safnari/blob/safnari-20260923a-rc3/docs/assets/release-v3-throughput.svg),
[size chart](https://github.com/ProvisioInsights/Safnari/blob/safnari-20260923a-rc3/docs/assets/release-v3-size.svg),
[raw evidence](https://github.com/ProvisioInsights/Safnari/tree/safnari-20260923a-rc3/artifacts/bench/rc3-controlled-20260923), and
[controlled workflow run](https://github.com/ProvisioInsights/Safnari/actions/runs/35880325070).
The charts exclude cold-cache scans and managed-delivery overhead.

## Release boundary

RC3 is for bounded validation, not general availability. Crash-transition and disk-full
delivery tests, healthy/slow/disconnected receiver overhead, and a 25–50 device pilot remain
open. Receiver acceptance is the acknowledgment boundary; consumers must deduplicate event IDs.
The release retains OTEL and does not include Kai integration.

The repository's performance dashboard is also repaired for macOS Bash 3.2 and Windows report
generation. It is a latest-run development dashboard, separate from the controlled comparison
above.
