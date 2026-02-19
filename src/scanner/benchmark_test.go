package scanner

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"safnari/config"
	"safnari/output"
)

var benchmarkFileDataSink *FileRecord
var benchmarkModulesSink []FileModule

func benchmarkScannerConfig() *config.Config {
	return &config.Config{
		ScanFiles:           true,
		ScanSensitive:       true,
		HashAlgorithms:      []string{"md5"},
		MaxFileSize:         1 << 20,
		MetadataMaxBytes:    1 << 20,
		SensitiveMaxPerType: 100,
		SensitiveMaxTotal:   1000,
		RedactSensitive:     "mask",
	}
}

func BenchmarkCollectFileData(b *testing.B) {
	tmp, err := os.CreateTemp("", "scanner-bench-*.txt")
	if err != nil {
		b.Fatal(err)
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.WriteString("hello test@example.com\napi-key: abcd1234\n"); err != nil {
		b.Fatal(err)
	}
	if err := tmp.Close(); err != nil {
		b.Fatal(err)
	}

	fi, err := os.Stat(tmp.Name())
	if err != nil {
		b.Fatal(err)
	}
	cfg := benchmarkScannerConfig()
	patterns := GetPatterns([]string{"email"}, nil, nil)
	prebuiltModules := buildFileModules(cfg, patterns)
	ctx := context.Background()

	b.Run("build-modules-per-call", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			data, err := collectFileData(ctx, tmp.Name(), fi, cfg, patterns, nil)
			if err != nil {
				b.Fatal(err)
			}
			benchmarkFileDataSink = data
		}
	})

	b.Run("reuse-prebuilt-modules", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			data, err := collectFileData(ctx, tmp.Name(), fi, cfg, patterns, prebuiltModules)
			if err != nil {
				b.Fatal(err)
			}
			benchmarkFileDataSink = data
		}
	})
}

func BenchmarkBuildFileModules(b *testing.B) {
	cfg := benchmarkScannerConfig()
	patterns := GetPatterns([]string{"email"}, nil, nil)

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		benchmarkModulesSink = buildFileModules(cfg, patterns)
	}
}

func BenchmarkProcessFileStatOverhead(b *testing.B) {
	tmp, err := os.CreateTemp("", "scanner-process-bench-*.txt")
	if err != nil {
		b.Fatal(err)
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.WriteString("minimal benchmark payload"); err != nil {
		b.Fatal(err)
	}
	if err := tmp.Close(); err != nil {
		b.Fatal(err)
	}

	fi, err := os.Stat(tmp.Name())
	if err != nil {
		b.Fatal(err)
	}

	cfg := &config.Config{
		StartPaths:    []string{filepath.Dir(tmp.Name())},
		ScanFiles:     false,
		ScanSensitive: false,
	}
	w := &output.Writer{}
	ctx := context.Background()
	modules := buildFileModules(cfg, nil)

	b.Run("stat-inside-worker", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			processFile(ctx, tmp.Name(), nil, cfg, w, nil, modules, true)
		}
	})

	b.Run("prefetched-fileinfo", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			processFile(ctx, tmp.Name(), fi, cfg, w, nil, modules, true)
		}
	})
}
