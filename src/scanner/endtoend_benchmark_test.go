package scanner

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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
		{name: "small_files", build: buildSmallFilesCorpus},
		{name: "mixed", build: buildMixedCorpus},
		{name: "mixed_heavy_tail", build: buildMixedHeavyTailCorpus},
		{name: "sensitive_dense", build: buildSensitiveDenseCorpus},
		{name: "duplicate_logs", build: buildDuplicateLogsCorpus},
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

func BenchmarkDeltaSecondRunCorpora(b *testing.B) {
	corpora := []struct {
		name   string
		build  func(*testing.B, string)
		mutate func(*testing.B, string)
	}{
		{
			name:   "duplicate_logs",
			build:  buildDuplicateLogsCorpus,
			mutate: mutateDuplicateLogsTail,
		},
	}
	for _, corpus := range corpora {
		corpus := corpus
		b.Run(corpus.name, func(b *testing.B) {
			b.Run("mtime", func(b *testing.B) {
				benchmarkDeltaSecondRunOnRoot(b, corpus.build, corpus.mutate, func(cfg *config.Config) {
					cfg.DeltaCacheMode = "mtime"
				})
			})
			b.Run("chunk", func(b *testing.B) {
				benchmarkDeltaSecondRunOnRoot(b, corpus.build, corpus.mutate, func(cfg *config.Config) {
					cfg.DeltaCacheMode = "chunk"
				})
			})
			b.Run("adaptive", func(b *testing.B) {
				benchmarkDeltaSecondRunOnRoot(b, corpus.build, corpus.mutate, nil)
			})
			b.Run("ultra", func(b *testing.B) {
				benchmarkDeltaSecondRunOnRoot(b, corpus.build, corpus.mutate, func(cfg *config.Config) {
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
		cfg := benchmarkConfig(root, outPath)
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

func benchmarkDeltaSecondRunOnRoot(
	b *testing.B,
	build func(*testing.B, string),
	mutate func(*testing.B, string),
	cfgMutate func(*config.Config),
) {
	b.Helper()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		workRoot := filepath.Join(b.TempDir(), fmt.Sprintf("delta-%03d", i))
		build(b, workRoot)
		lastScanFile := filepath.Join(workRoot, ".safnari_last_scan")

		seedCfg := benchmarkConfig(workRoot, filepath.Join(workRoot, "seed.ndjson"))
		if cfgMutate != nil {
			cfgMutate(seedCfg)
		}
		seedCfg.DeltaScan = true
		seedCfg.LastScanFile = lastScanFile
		metrics := &output.Metrics{}
		writer, err := output.New(seedCfg, &systeminfo.SystemInfo{RunningProcesses: []systeminfo.ProcessInfo{}}, metrics)
		if err != nil {
			b.Fatalf("seed output init: %v", err)
		}
		if err := ScanFiles(context.Background(), seedCfg, metrics, writer); err != nil {
			_ = writer.Close()
			b.Fatalf("seed scan failed: %v", err)
		}
		if err := writer.Close(); err != nil {
			b.Fatalf("seed close failed: %v", err)
		}

		time.Sleep(1100 * time.Millisecond)
		if mutate != nil {
			mutate(b, workRoot)
		}

		deltaCfg := benchmarkConfig(workRoot, filepath.Join(workRoot, "delta.ndjson"))
		if cfgMutate != nil {
			cfgMutate(deltaCfg)
		}
		deltaCfg.DeltaScan = true
		deltaCfg.LastScanFile = lastScanFile

		b.StartTimer()
		deltaMetrics := &output.Metrics{}
		deltaWriter, err := output.New(deltaCfg, &systeminfo.SystemInfo{RunningProcesses: []systeminfo.ProcessInfo{}}, deltaMetrics)
		if err != nil {
			b.Fatalf("delta output init: %v", err)
		}
		if err := ScanFiles(context.Background(), deltaCfg, deltaMetrics, deltaWriter); err != nil {
			_ = deltaWriter.Close()
			b.Fatalf("delta scan failed: %v", err)
		}
		if err := deltaWriter.Close(); err != nil {
			b.Fatalf("delta close failed: %v", err)
		}
		b.StopTimer()
	}
}

func benchmarkConfig(root, outPath string) *config.Config {
	return &config.Config{
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
		DeltaCacheMode:       "chunk",
		DeltaCacheDir:        filepath.Join(root, ".safnari-delta-cache"),
		DeltaCacheMaxBytes:   1 << 28,
		PerfProfile:          "adaptive",
		SensitiveEngine:      "auto",
		SensitiveLongtail:    "sampled",
		SensitiveWindowBytes: 4096,
		ContentReadMode:      "auto",
		StreamChunkSize:      256 * 1024,
		StreamOverlapBytes:   512,
		JSONLayout:           "ndjson",
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

func buildSmallFilesCorpus(b *testing.B, root string) {
	b.Helper()
	payload := "ALPHA test@example.com api_key=abcd1234\n"
	for d := 0; d < 48; d++ {
		dir := filepath.Join(root, fmt.Sprintf("small-%03d", d))
		if err := os.MkdirAll(dir, 0755); err != nil {
			b.Fatalf("mkdir: %v", err)
		}
		for f := 0; f < 64; f++ {
			path := filepath.Join(dir, fmt.Sprintf("tiny-%03d.txt", f))
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
	fixtureJWT := "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature" // gitleaks:allow
	payload := strings.Repeat(
		"user=test@example.com ssn=123-45-6789 cc=4111-1111-1111-1111 aws=AKIA"+"ABCDEFGHIJKLMNOP jwt="+fixtureJWT+"\n",
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

func buildMixedHeavyTailCorpus(b *testing.B, root string) {
	b.Helper()
	buildSmallFilesCorpus(b, root)
	largeDir := filepath.Join(root, "heavy")
	if err := os.MkdirAll(largeDir, 0755); err != nil {
		b.Fatalf("mkdir: %v", err)
	}
	largeChunk := strings.Repeat("ALPHA test@example.com api_key=abcd1234\n", 16384)
	for i := 0; i < 6; i++ {
		path := filepath.Join(largeDir, fmt.Sprintf("whale-%03d.log", i))
		if err := os.WriteFile(path, []byte(largeChunk), 0644); err != nil {
			b.Fatalf("write: %v", err)
		}
	}
}

func buildDuplicateLogsCorpus(b *testing.B, root string) {
	b.Helper()
	logDir := filepath.Join(root, "duplicate-logs")
	if err := os.MkdirAll(logDir, 0755); err != nil {
		b.Fatalf("mkdir: %v", err)
	}
	fixtureJWT := "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature" // gitleaks:allow
	payload := strings.Repeat(
		"ALPHA user=test@example.com api_key=abcd1234 ssn=123-45-6789 jwt="+fixtureJWT+"\n",
		8192,
	)
	for i := 0; i < 10; i++ {
		path := filepath.Join(logDir, fmt.Sprintf("replica-%03d.log", i))
		if err := os.WriteFile(path, []byte(payload), 0644); err != nil {
			b.Fatalf("write: %v", err)
		}
	}
}

func mutateDuplicateLogsTail(b *testing.B, root string) {
	b.Helper()
	matches, err := filepath.Glob(filepath.Join(root, "duplicate-logs", "*.log"))
	if err != nil {
		b.Fatalf("glob: %v", err)
	}
	tail := []byte("ALPHA mutation=test@example.com api_key=tailchange\n")
	for _, path := range matches {
		f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
		if err != nil {
			b.Fatalf("open append: %v", err)
		}
		if _, err := f.Write(tail); err != nil {
			_ = f.Close()
			b.Fatalf("append: %v", err)
		}
		if err := f.Close(); err != nil {
			b.Fatalf("close append: %v", err)
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
