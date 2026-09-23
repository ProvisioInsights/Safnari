package scanner

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

func TestFastWalkerReadsWideAndDeepDirectories(t *testing.T) {
	root := t.TempDir()
	for i := range 300 {
		if err := os.WriteFile(filepath.Join(root, fmt.Sprintf("file-%03d", i)), []byte("x"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	deep := root
	for range 20 {
		deep = filepath.Join(deep, "next")
		if err := os.Mkdir(deep, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(deep, "last"), []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	count := 0
	err := (fastWalker{}).Walk(context.Background(), root, func(_ string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			count++
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if count != 301 {
		t.Fatalf("walked %d files, want 301", count)
	}
}
