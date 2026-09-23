package scanner

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"safnari/config"
)

func TestDirectoryRootCacheRejectsSymlinkEscape(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("rooted scan path is disabled on Windows")
	}
	rootPath := t.TempDir()
	inside := filepath.Join(rootPath, "inside")
	if err := os.Mkdir(inside, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(inside, "file.txt")
	if err := os.WriteFile(path, []byte("inside"), 0600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	anchor, err := os.OpenRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	cache := newDirectoryRootCache(anchor)
	defer cache.Close()
	source := &FileContext{Path: path, Info: info, rootCache: cache,
		rootRelativePath: filepath.Join("inside", "file.txt")}
	if _, err := source.Source(); err != nil {
		t.Fatal(err)
	}
	_ = source.Close()

	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "file.txt"), []byte("outside"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(inside, filepath.Join(rootPath, "moved")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, inside); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	// The cached directory capability stays pinned to the directory that was
	// inside the root; it cannot follow the new pathname to outside content.
	source = &FileContext{Path: path, Info: info, rootCache: cache,
		rootRelativePath: filepath.Join("inside", "file.txt")}
	opened, err := source.Source()
	if err != nil {
		t.Fatal(err)
	}
	if string(opened.Header()) != "inside" {
		t.Fatalf("cached directory opened %q after symlink swap", opened.Header())
	}
	_ = source.Close()
	if err := os.Symlink(outside, filepath.Join(rootPath, "new-link")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if file, err := cache.Open(filepath.Join("new-link", "file.txt")); err == nil {
		_ = file.Close()
		t.Fatal("uncached directory followed a symlink outside the root")
	}
}

func TestDirectoryRootCacheRejectsReplacedFile(t *testing.T) {
	rootPath := t.TempDir()
	path := filepath.Join(rootPath, "file.txt")
	if err := os.WriteFile(path, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	anchor, err := os.OpenRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	cache := newDirectoryRootCache(anchor)
	defer cache.Close()
	replacement := filepath.Join(rootPath, "replacement.txt")
	if err := os.WriteFile(replacement, []byte("replacement"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacement, path); err != nil {
		t.Fatal(err)
	}
	fc := &FileContext{Path: path, Info: info, rootCache: cache, rootRelativePath: "file.txt"}
	if source, err := fc.Source(); err == nil {
		_ = source.Close()
		t.Fatal("accepted a replaced file with stale traversal metadata")
	}
	if _, err := collectFileDataWithRootCache(context.Background(), path, info,
		&config.Config{ScanFiles: true}, nil, nil, nil, cache, "file.txt"); err == nil {
		t.Fatal("changed file was not reported as a collection error")
	}
}

func TestDirectoryRootCacheRejectsLeafSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("rooted scan path is disabled on Windows")
	}
	rootPath := t.TempDir()
	dir := filepath.Join(rootPath, "inside")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "secret.txt")
	if err := os.WriteFile(outside, []byte("outside"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "link.txt")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	anchor, err := os.OpenRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	cache := newDirectoryRootCache(anchor)
	defer cache.Close()
	if file, err := cache.Open(filepath.Join("inside", "link.txt")); err == nil {
		_ = file.Close()
		t.Fatal("followed a symlink leaf outside the scan root")
	}
}

func TestDirectoryRootCacheIsBounded(t *testing.T) {
	rootPath := t.TempDir()
	anchor, err := os.OpenRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	cache := newDirectoryRootCache(anchor)
	defer cache.Close()
	for i := range maxCachedDirectoryRoots + 8 {
		dir := fmt.Sprintf("dir-%03d", i)
		if err := os.Mkdir(filepath.Join(rootPath, dir), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(rootPath, dir, "file"), []byte("x"), 0600); err != nil {
			t.Fatal(err)
		}
		f, err := cache.Open(filepath.Join(dir, "file"))
		if err != nil {
			t.Fatal(err)
		}
		_ = f.Close()
	}
	if got := len(cache.entries); got > maxCachedDirectoryRoots {
		t.Fatalf("cached %d directory roots, max %d", got, maxCachedDirectoryRoots)
	}
}

func TestFileTimesFromTraversalInfoMatchesPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "file.txt")
	if err := os.WriteFile(path, []byte("sample"), 0600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	fromPath, err := fileTimes(path)
	if err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	fromOpenFile, err := fileTimesFromOpenFile(info, file)
	if err != nil {
		t.Fatal(err)
	}
	if fromOpenFile != fromPath {
		t.Fatalf("timestamp mismatch: descriptor=%+v path=%+v", fromOpenFile, fromPath)
	}
}

func TestDirectoryRootCacheCloseDrainsFiles(t *testing.T) {
	rootPath := t.TempDir()
	if err := os.WriteFile(filepath.Join(rootPath, "file.txt"), []byte("sample"), 0600); err != nil {
		t.Fatal(err)
	}
	anchor, err := os.OpenRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	cache := newDirectoryRootCache(anchor)
	file, err := cache.Open("file.txt")
	if err != nil {
		cache.Close()
		t.Fatal(err)
	}
	cache.CloseFile(file)
	cache.Close()
	if _, err := file.Stat(); err == nil {
		t.Fatal("scan returned before pending file close completed")
	}
}
