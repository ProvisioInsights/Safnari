package scanner

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"safnari/config"
	"safnari/output"
	"safnari/systeminfo"
)

func BenchmarkScanFilesSyntheticTree(b *testing.B) {
	root := b.TempDir()
	buildSyntheticCorpus(b, root, 48, 8)

	b.Run("adaptive", func(b *testing.B) {
		benchmarkScanFilesOnRoot(b, root, nil)
	})

	b.Run("ultra", func(b *testing.B) {
		benchmarkScanFilesOnRoot(b, root, func(cfg *config.Config) {
			cfg.PerfProfile = "ultra"
			cfg.SensitiveEngine = "deterministic"
			cfg.SensitiveLongtail = "off"
			cfg.ContentReadMode = "stream"
			cfg.MmapMinSize = 128 * 1024
			cfg.SimdFastpath = false
		})
	})
}

func BenchmarkScanFilesCorpora(b *testing.B) {
	corpora := []struct {
		name  string
		build func(*testing.B, string)
	}{
		{name: "mixed", build: buildMixedCorpus},
		{name: "sensitive_dense", build: buildSensitiveDenseCorpus},
		{name: "large_files", build: buildLargeFilesCorpus},
	}
	for _, corpus := range corpora {
		corpus := corpus
		b.Run(corpus.name, func(b *testing.B) {
			root := b.TempDir()
			corpus.build(b, root)
			b.Run("adaptive", func(b *testing.B) {
				benchmarkScanFilesOnRoot(b, root, nil)
			})
			b.Run("ultra", func(b *testing.B) {
				benchmarkScanFilesOnRoot(b, root, func(cfg *config.Config) {
					cfg.PerfProfile = "ultra"
					cfg.SensitiveEngine = "deterministic"
					cfg.SensitiveLongtail = "off"
					cfg.ContentReadMode = "stream"
					cfg.MmapMinSize = 128 * 1024
					cfg.SimdFastpath = false
				})
			})
		})
	}
}

func benchmarkScanFilesOnRoot(b *testing.B, root string, mutate func(cfg *config.Config)) {
	b.Helper()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		outPath := filepath.Join(b.TempDir(), "bench.ndjson")
		cfg := &config.Config{
			StartPaths:           []string{root},
			ScanFiles:            true,
			ScanSensitive:        true,
			ScanProcesses:        false,
			CollectSystemInfo:    false,
			OutputFormat:         "json",
			OutputFileName:       outPath,
			ConcurrencyLevel:     2,
			NiceLevel:            "medium",
			HashAlgorithms:       []string{"md5"},
			SearchTerms:          []string{"ALPHA", "email"},
			MaxFileSize:          4 << 20,
			MaxOutputFileSize:    50 << 20,
			LogLevel:             "error",
			MaxIOPerSecond:       0,
			IncludeDataTypes:     []string{"email", "api_key", "aws_access_key", "jwt_token", "ssn"},
			CustomPatterns:       map[string]string{},
			SensitiveMaxPerType:  100,
			SensitiveMaxTotal:    1000,
			MetadataMaxBytes:     1 << 20,
			RedactSensitive:      "",
			CollectXattrs:        false,
			CollectACL:           false,
			CollectScheduled:     false,
			CollectUsers:         false,
			CollectGroups:        false,
			CollectAdmins:        false,
			ScanADS:              false,
			SkipCount:            true,
			AutoTune:             false,
			PerfProfile:          "adaptive",
			SensitiveEngine:      "auto",
			SensitiveLongtail:    "sampled",
			SensitiveWindowBytes: 4096,
			ContentReadMode:      "auto",
			StreamChunkSize:      256 * 1024,
			StreamOverlapBytes:   512,
			JSONLayout:           "ndjson",
		}
		if mutate != nil {
			mutate(cfg)
		}

		metrics := &output.Metrics{}
		writer, err := output.New(cfg, &systeminfo.SystemInfo{RunningProcesses: []systeminfo.ProcessInfo{}}, metrics)
		if err != nil {
			b.Fatalf("output init: %v", err)
		}
		if err := ScanFiles(context.Background(), cfg, metrics, writer); err != nil {
			writer.Close()
			b.Fatalf("scan failed: %v", err)
		}
		writer.Close()
	}
}

func buildSyntheticCorpus(b *testing.B, root string, dirs, filesPerDir int) {
	b.Helper()
	payload := strings.Repeat("ALPHA test@example.com api_key=abcd1234\n", 64)
	for d := 0; d < dirs; d++ {
		dir := filepath.Join(root, fmt.Sprintf("dir-%03d", d))
		if err := os.MkdirAll(dir, 0755); err != nil {
			b.Fatalf("mkdir: %v", err)
		}
		for f := 0; f < filesPerDir; f++ {
			path := filepath.Join(dir, fmt.Sprintf("file-%03d.txt", f))
			if err := os.WriteFile(path, []byte(payload), 0644); err != nil {
				b.Fatalf("write: %v", err)
			}
		}
	}
}

func buildMixedCorpus(b *testing.B, root string) {
	b.Helper()
	buildSyntheticCorpus(b, root, 24, 8)
	for i := 0; i < 16; i++ {
		binPath := filepath.Join(root, "binary", fmt.Sprintf("blob-%03d.bin", i))
		if err := os.MkdirAll(filepath.Dir(binPath), 0755); err != nil {
			b.Fatalf("mkdir: %v", err)
		}
		payload := []byte(strings.Repeat("\x00\x01\x02\x03", 4096))
		if err := os.WriteFile(binPath, payload, 0644); err != nil {
			b.Fatalf("write: %v", err)
		}
	}
}

func buildSensitiveDenseCorpus(b *testing.B, root string) {
	b.Helper()
	payload := strings.Repeat(
		"user=test@example.com ssn=123-45-6789 cc=4111-1111-1111-1111 aws=AKIA"+"ABCDEFGHIJKLMNOP jwt=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature\n",
		96,
	)
	for d := 0; d < 32; d++ {
		dir := filepath.Join(root, fmt.Sprintf("sens-%03d", d))
		if err := os.MkdirAll(dir, 0755); err != nil {
			b.Fatalf("mkdir: %v", err)
		}
		for f := 0; f < 6; f++ {
			path := filepath.Join(dir, fmt.Sprintf("secret-%03d.txt", f))
			if err := os.WriteFile(path, []byte(payload), 0644); err != nil {
				b.Fatalf("write: %v", err)
			}
		}
	}
}

func buildLargeFilesCorpus(b *testing.B, root string) {
	b.Helper()
	chunk := strings.Repeat("ALPHA test@example.com api_key=abcd1234\n", 8192)
	for i := 0; i < 12; i++ {
		dir := filepath.Join(root, "large")
		if err := os.MkdirAll(dir, 0755); err != nil {
			b.Fatalf("mkdir: %v", err)
		}
		path := filepath.Join(dir, fmt.Sprintf("large-%03d.log", i))
		if err := os.WriteFile(path, []byte(chunk), 0644); err != nil {
			b.Fatalf("write: %v", err)
		}
	}
}
