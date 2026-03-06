package scanner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"safnari/config"
)

func BenchmarkChunkSource(b *testing.B) {
	root := b.TempDir()
	path := filepath.Join(root, "chunk-source.log")
	payload := []byte(strings.Repeat("ALPHA test@example.com api_key=abcd1234\n", 8192))
	if err := os.WriteFile(path, payload, 0644); err != nil {
		b.Fatalf("write benchmark file: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		b.Fatalf("stat benchmark file: %v", err)
	}
	cfg := &config.Config{StreamChunkSize: 256 * 1024}

	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	for i := 0; i < b.N; i++ {
		source, err := openChunkSource(path, info, cfg)
		if err != nil {
			b.Fatalf("open chunk source: %v", err)
		}
		if err := source.Scan(0, func(chunk []byte, _ int64) error {
			benchmarkChunkBytes += len(chunk)
			return nil
		}); err != nil {
			_ = source.Close()
			b.Fatalf("scan chunk source: %v", err)
		}
		if err := source.Close(); err != nil {
			b.Fatalf("close chunk source: %v", err)
		}
	}
}

func BenchmarkStreamAho(b *testing.B) {
	payload := []byte(strings.Repeat("ALPHA beta gamma test@example.com\n", 8192))
	terms := []string{"ALPHA", "example.com", "delta"}

	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	for i := 0; i < b.N; i++ {
		counter := newStreamAhoCounter(terms)
		counter.Consume(payload)
		benchmarkSearchHits = counter.Results()
	}
}

func BenchmarkDeltaChunkCache(b *testing.B) {
	root := b.TempDir()
	cacheDir := filepath.Join(root, "cache")
	cfg := &config.Config{
		DeltaScan:          true,
		DeltaCacheMode:     "chunk",
		DeltaCacheDir:      cacheDir,
		DeltaCacheMaxBytes: 8 << 20,
		SearchTerms:        []string{"ALPHA"},
	}
	cache, err := openDeltaChunkCache(cfg)
	if err != nil {
		b.Fatalf("open delta cache: %v", err)
	}
	defer func() { _ = cache.Close() }()

	entry := &deltaCachedFile{
		ConfigFingerprint: "bench",
		ChunkSize:         deltaCacheChunkSize,
		ReadLimit:         0,
		ChunkHashes:       []string{"a", "b", "c"},
		Chunks: []deltaCachedChunk{
			{SearchCounts: map[string]int{"ALPHA": 1}},
			{SearchCounts: map[string]int{"ALPHA": 1}},
			{SearchCounts: map[string]int{"ALPHA": 1}},
		},
		SearchHits: map[string]int{"ALPHA": 3},
	}
	if err := cache.Store("bench.log", entry); err != nil {
		b.Fatalf("seed cache: %v", err)
	}

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		cached, ok, err := cache.Load("bench.log", "bench", 0)
		if err != nil {
			b.Fatalf("load cache entry: %v", err)
		}
		if !ok || len(cached.ChunkHashes) != 3 {
			b.Fatalf("unexpected cache entry: ok=%t chunks=%d", ok, len(cached.ChunkHashes))
		}
	}
}

var (
	benchmarkChunkBytes int
	benchmarkSearchHits map[string]int
)
