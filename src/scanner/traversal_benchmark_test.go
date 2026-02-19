package scanner

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"safnari/config"
	"safnari/utils"
)

func BenchmarkTraversalDeepTree(b *testing.B) {
	root := b.TempDir()
	createDeepTree(b, root, 120, 6)
	benchmarkTraversalStrategies(b, root)
}

func BenchmarkTraversalWideTree(b *testing.B) {
	root := b.TempDir()
	createWideTree(b, root, 220, 5)
	benchmarkTraversalStrategies(b, root)
}

func benchmarkTraversalStrategies(b *testing.B, root string) {
	b.Helper()
	matcher := utils.NewPatternMatcher(nil, nil)
	ctx := context.Background()

	cfg := &config.Config{}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		count, err := countTotalFiles(ctx, root, cfg, time.Time{}, matcher)
		if err != nil {
			b.Fatalf("count failed: %v", err)
		}
		if count == 0 {
			b.Fatal("expected non-zero file count")
		}
	}
}

func createDeepTree(b *testing.B, root string, depth, filesPerLevel int) {
	b.Helper()
	current := root
	for d := 0; d < depth; d++ {
		current = filepath.Join(current, fmt.Sprintf("d-%03d", d))
		if err := os.MkdirAll(current, 0755); err != nil {
			b.Fatalf("mkdir: %v", err)
		}
		for f := 0; f < filesPerLevel; f++ {
			path := filepath.Join(current, fmt.Sprintf("file-%03d.txt", f))
			if err := os.WriteFile(path, []byte("benchmark"), 0644); err != nil {
				b.Fatalf("write: %v", err)
			}
		}
	}
}

func createWideTree(b *testing.B, root string, dirs, filesPerDir int) {
	b.Helper()
	for d := 0; d < dirs; d++ {
		dir := filepath.Join(root, fmt.Sprintf("w-%03d", d))
		if err := os.MkdirAll(dir, 0755); err != nil {
			b.Fatalf("mkdir: %v", err)
		}
		for f := 0; f < filesPerDir; f++ {
			path := filepath.Join(dir, fmt.Sprintf("file-%03d.txt", f))
			if err := os.WriteFile(path, []byte("benchmark"), 0644); err != nil {
				b.Fatalf("write: %v", err)
			}
		}
	}
}
