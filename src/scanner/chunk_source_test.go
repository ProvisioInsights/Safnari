package scanner

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"safnari/config"
)

func TestOpenChunkSourceRejectsReplacedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sample.txt")
	if err := os.WriteFile(path, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	replacement := filepath.Join(filepath.Dir(path), "replacement.txt")
	if err := os.WriteFile(replacement, []byte("replacement"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacement, path); err != nil {
		t.Fatal(err)
	}
	if source, err := openChunkSource(path, info, nil); err == nil {
		_ = source.Close()
		t.Fatal("accepted a replacement file after traversal")
	}
}

func TestChunkSourceScanReusesHeaderWithoutChangingStream(t *testing.T) {
	for _, size := range []int{0, 1, 127, 4096, 4097, 9000} {
		payload := make([]byte, size)
		for i := range payload {
			payload[i] = byte(i % 251)
		}
		path := filepath.Join(t.TempDir(), "sample.log")
		if err := os.WriteFile(path, payload, 0600); err != nil {
			t.Fatal(err)
		}
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		for _, chunkSize := range []int{37, 4096, 8192} {
			for _, limit := range []int64{0, 1, 4095, 4096, 4097, 6000} {
				source, err := openChunkSource(path, info, &config.Config{StreamChunkSize: chunkSize})
				if err != nil {
					t.Fatal(err)
				}
				var got []byte
				err = source.Scan(limit, func(chunk []byte, offset int64) error {
					if offset != int64(len(got)) {
						t.Fatalf("size=%d chunk=%d limit=%d: offset=%d want=%d", size, chunkSize, limit, offset, len(got))
					}
					got = append(got, chunk...)
					return nil
				})
				if err != nil {
					t.Fatal(err)
				}
				if err := source.Close(); err != nil {
					t.Fatal(err)
				}
				want := payload
				if limit > 0 && int64(len(want)) > limit {
					want = want[:limit]
				}
				if !bytes.Equal(got, want) {
					t.Fatalf("size=%d chunk=%d limit=%d: stream differs", size, chunkSize, limit)
				}
			}
		}
	}
}

func TestHeaderBoundaryRetainsHashSearchAndSensitiveMatches(t *testing.T) {
	content := strings.Repeat("x", chunkSourceHeaderBytes-2) + "ALPHA test@example.com\n"
	path := filepath.Join(t.TempDir(), "boundary.log")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{
		ScanFiles: true, ScanSensitive: true,
		HashAlgorithms: []string{"sha256"}, SearchTerms: []string{"ALPHA"},
		IncludeDataTypes: []string{"email"}, StreamChunkSize: 1024,
	}
	patterns := GetPatterns(cfg.IncludeDataTypes, nil, nil)
	data, err := collectFileData(context.Background(), path, info, cfg, patterns,
		buildFileModules(cfg, patterns), nil)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(content))
	if data.Hashes["sha256"] != hex.EncodeToString(sum[:]) {
		t.Fatalf("hash mismatch: %v", data.Hashes)
	}
	if data.SearchHits["ALPHA"] != 1 || data.SensitiveDataMatchCounts["email"] != 1 {
		t.Fatalf("boundary matches missing: search=%v sensitive=%v",
			data.SearchHits, data.SensitiveDataMatchCounts)
	}
}
