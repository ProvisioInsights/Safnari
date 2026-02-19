package hasher

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"hash"
	"io"
	"os"
	"sync"

	"safnari/logger"
)

const (
	hashBufferSmallSize      = 32 * 1024
	hashBufferLargeSize      = 128 * 1024
	hashLargeBufferThreshold = 256 * 1024
)

var hashBufferSmallPool = sync.Pool{
	New: func() interface{} {
		buf := make([]byte, hashBufferSmallSize)
		return &buf
	},
}

var hashBufferLargePool = sync.Pool{
	New: func() interface{} {
		buf := make([]byte, hashBufferLargeSize)
		return &buf
	},
}

func ComputeHashes(path string, algorithms []string) map[string]string {
	hashes := make(map[string]string, len(algorithms))

	file, err := os.Open(path)
	if err != nil {
		logger.Warnf("Failed to open file for hashing %s: %v", path, err)
		return hashes
	}
	defer file.Close()

	type hasherEntry struct {
		name string
		h    hash.Hash
	}
	hashers := make([]hasherEntry, 0, len(algorithms))
	seen := make(map[string]struct{}, len(algorithms))
	for _, algo := range algorithms {
		if _, ok := seen[algo]; ok {
			continue
		}
		switch algo {
		case "md5":
			hashers = append(hashers, hasherEntry{name: "md5", h: md5.New()})
			seen[algo] = struct{}{}
		case "sha1":
			hashers = append(hashers, hasherEntry{name: "sha1", h: sha1.New()})
			seen[algo] = struct{}{}
		case "sha256":
			hashers = append(hashers, hasherEntry{name: "sha256", h: sha256.New()})
			seen[algo] = struct{}{}
		default:
			logger.Warnf("Unsupported hash algorithm: %s", algo)
		}
	}

	if len(hashers) > 0 {
		bufferPool := &hashBufferSmallPool
		if info, statErr := file.Stat(); statErr == nil && info.Size() >= hashLargeBufferThreshold {
			bufferPool = &hashBufferLargePool
		}
		bufferPtr := bufferPool.Get().(*[]byte)
		buffer := *bufferPtr
		for {
			n, readErr := file.Read(buffer)
			if n > 0 {
				chunk := buffer[:n]
				for i := range hashers {
					if _, err := hashers[i].h.Write(chunk); err != nil {
						logger.Warnf("Failed to update hash %s for %s: %v", hashers[i].name, path, err)
					}
				}
			}
			if readErr != nil {
				if readErr != io.EOF {
					logger.Warnf("Failed to compute hashes for %s: %v", path, readErr)
				}
				break
			}
		}
		bufferPool.Put(bufferPtr)
	}

	for i := range hashers {
		hashes[hashers[i].name] = hex.EncodeToString(hashers[i].h.Sum(nil))
	}

	return hashes
}
