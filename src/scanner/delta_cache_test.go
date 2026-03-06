package scanner

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"safnari/config"
)

func TestDeltaChunkCacheReuseMatchesFreshCollection(t *testing.T) {
	root := t.TempDir()
	cacheDir := filepath.Join(root, "delta-cache")
	path := filepath.Join(root, "replica.log")
	payload := strings.Repeat("ALPHA test@example.com api_key=abcd1234\n", 65536)
	if err := os.WriteFile(path, []byte(payload), 0644); err != nil {
		t.Fatalf("write seed file: %v", err)
	}

	cfg := &config.Config{
		ScanFiles:           true,
		ScanSensitive:       true,
		DeltaScan:           true,
		DeltaCacheMode:      "chunk",
		DeltaCacheDir:       cacheDir,
		DeltaCacheMaxBytes:  32 << 20,
		HashAlgorithms:      []string{"md5"},
		SearchTerms:         []string{"ALPHA", "example.com"},
		ContentScanMaxBytes: 0,
		SensitiveEngine:     "deterministic",
		SensitiveLongtail:   "off",
		SensitiveMaxPerType: 64,
		SensitiveMaxTotal:   128,
		IncludeDataTypes:    []string{"email", "api_key"},
		FuzzyHash:           false,
	}
	patterns := GetPatterns(cfg.IncludeDataTypes, nil, nil)
	cache, err := openDeltaChunkCache(cfg)
	if err != nil {
		t.Fatalf("open delta cache: %v", err)
	}
	defer func() { _ = cache.Close() }()

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat seed file: %v", err)
	}
	seed, err := collectFileData(context.Background(), path, info, cfg, patterns, buildFileModules(cfg, patterns), cache)
	if err != nil {
		t.Fatalf("collect seed file: %v", err)
	}
	if len(seed.SearchHits) == 0 || len(seed.SensitiveData) == 0 {
		t.Fatalf("expected seeded cache output, got %+v", seed)
	}

	entry, ok, err := cache.Load(path, deltaCacheFingerprint(cfg, patterns), 0)
	if err != nil {
		t.Fatalf("load cached seed: %v", err)
	}
	if !ok || len(entry.Chunks) < 2 {
		t.Fatalf("expected multi-chunk cache entry, ok=%t chunks=%d", ok, len(entry.Chunks))
	}

	if err := os.WriteFile(path, []byte(payload+"ALPHA tail=test@example.com api_key=tailchange\n"), 0644); err != nil {
		t.Fatalf("rewrite mutated file: %v", err)
	}

	info, err = os.Stat(path)
	if err != nil {
		t.Fatalf("stat mutated file: %v", err)
	}
	withCache, err := collectFileData(context.Background(), path, info, cfg, patterns, buildFileModules(cfg, patterns), cache)
	if err != nil {
		t.Fatalf("collect mutated file with cache: %v", err)
	}
	fresh, err := collectFileData(context.Background(), path, info, cfg, patterns, buildFileModules(cfg, patterns), nil)
	if err != nil {
		t.Fatalf("collect mutated file without cache: %v", err)
	}

	if !reflect.DeepEqual(withCache.Hashes, fresh.Hashes) {
		t.Fatalf("hash mismatch with delta cache: cached=%v fresh=%v", withCache.Hashes, fresh.Hashes)
	}
	if !reflect.DeepEqual(withCache.SearchHits, fresh.SearchHits) {
		t.Fatalf("search mismatch with delta cache: cached=%v fresh=%v", withCache.SearchHits, fresh.SearchHits)
	}
	if !reflect.DeepEqual(withCache.SensitiveData, fresh.SensitiveData) {
		t.Fatalf("sensitive data mismatch with delta cache: cached=%v fresh=%v", withCache.SensitiveData, fresh.SensitiveData)
	}
	if !reflect.DeepEqual(withCache.SensitiveDataMatchCounts, fresh.SensitiveDataMatchCounts) {
		t.Fatalf("sensitive counts mismatch with delta cache: cached=%v fresh=%v", withCache.SensitiveDataMatchCounts, fresh.SensitiveDataMatchCounts)
	}
}

func TestInternalArtifactFilterSkipsDeltaCacheDir(t *testing.T) {
	root := t.TempDir()
	cacheDir := filepath.Join(root, "cache")
	cfg := &config.Config{
		OutputFileName:     filepath.Join(root, "out.ndjson"),
		LastScanFile:       filepath.Join(root, ".safnari_last_scan"),
		DiagDir:            filepath.Join(root, "diag"),
		DeltaCacheDir:      cacheDir,
		DeltaCacheMode:     "chunk",
		DeltaCacheMaxBytes: 1 << 20,
	}
	filter := newInternalArtifactFilter(cfg)
	candidate := filepath.Join(cacheDir, "abc123.json")
	if !filter.ShouldSkip(candidate) {
		t.Fatalf("expected delta cache artifact to be skipped: %s", candidate)
	}
}

func TestPickScheduledTaskPrefersAgedLargeWork(t *testing.T) {
	lanes := map[schedulerLane][]scheduledTask{
		schedulerLaneSmall: []scheduledTask{
			{task: fileScanTask{path: "small"}, lane: schedulerLaneSmall, enqueuedAt: time.Now()},
		},
		schedulerLaneMedium: nil,
		schedulerLaneLarge: []scheduledTask{
			{
				task:       fileScanTask{path: "large"},
				lane:       schedulerLaneLarge,
				enqueuedAt: time.Now().Add(-schedulerAgingThreshold - 10*time.Millisecond),
			},
		},
		schedulerLaneExpensive: nil,
	}
	order := []schedulerLane{schedulerLaneSmall, schedulerLaneMedium, schedulerLaneLarge}
	index := 0

	task, ok := pickScheduledTask(lanes, order, &index)
	if !ok {
		t.Fatal("expected scheduled task")
	}
	if task.task.path != "large" {
		t.Fatalf("expected aged large task first, got %q", task.task.path)
	}
}

func TestOpenDeltaChunkCacheDefaultsEmptyModeToChunk(t *testing.T) {
	cfg := &config.Config{
		DeltaScan:          true,
		DeltaCacheMode:     "",
		DeltaCacheDir:      filepath.Join(t.TempDir(), "delta-cache"),
		DeltaCacheMaxBytes: 1 << 20,
	}
	cache, err := openDeltaChunkCache(cfg)
	if err != nil {
		t.Fatalf("open delta cache: %v", err)
	}
	if cache == nil {
		t.Fatal("expected cache to open when delta-cache-mode is unset")
	}
	if err := cache.Close(); err != nil {
		t.Fatalf("close delta cache: %v", err)
	}
}

func TestShouldChunkCacheSensitiveAllCriticalIgnoresLongtail(t *testing.T) {
	cfg := &config.Config{
		SensitiveLongtail:  "sampled",
		SensitiveMatchMode: "all",
	}
	patterns := GetPatterns([]string{"email", "api_key", "ssn"}, nil, nil)
	if !shouldChunkCacheSensitive(cfg, patterns) {
		t.Fatal("expected all-critical patterns to be chunk-cacheable under sampled longtail mode")
	}
	cfg.SensitiveMatchMode = "first"
	if shouldChunkCacheSensitive(cfg, patterns) {
		t.Fatal("expected first-match mode to bypass chunk-sensitive cache reuse")
	}
}
