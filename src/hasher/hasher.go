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

	"lukechampine.com/blake3"
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

type entry struct {
	name string
	h    hash.Hash
}

type Set struct {
	hashers []entry
}

func NewSet(algorithms []string) *Set {
	hashers := make([]entry, 0, len(algorithms))
	seen := make(map[string]struct{}, len(algorithms))
	for _, algo := range algorithms {
		if _, ok := seen[algo]; ok {
			continue
		}
		switch algo {
		case "md5":
			hashers = append(hashers, entry{name: "md5", h: md5.New()})
			seen[algo] = struct{}{}
		case "sha1":
			hashers = append(hashers, entry{name: "sha1", h: sha1.New()})
			seen[algo] = struct{}{}
		case "sha256":
			hashers = append(hashers, entry{name: "sha256", h: sha256.New()})
			seen[algo] = struct{}{}
		case "blake3":
			hashers = append(hashers, entry{name: "blake3", h: blake3.New(32, nil)})
			seen[algo] = struct{}{}
		default:
			logger.Warnf("Unsupported hash algorithm: %s", algo)
		}
	}
	return &Set{hashers: hashers}
}

func (s *Set) Enabled() bool {
	return s != nil && len(s.hashers) > 0
}

func (s *Set) Write(chunk []byte) {
	if s == nil {
		return
	}
	for i := range s.hashers {
		if _, err := s.hashers[i].h.Write(chunk); err != nil {
			logger.Warnf("Failed to update hash %s: %v", s.hashers[i].name, err)
		}
	}
}

func (s *Set) Sum() map[string]string {
	if s == nil {
		return map[string]string{}
	}
	hashes := make(map[string]string, len(s.hashers))
	for i := range s.hashers {
		hashes[s.hashers[i].name] = hex.EncodeToString(s.hashers[i].h.Sum(nil))
	}
	return hashes
}

func ComputeHashes(path string, algorithms []string) map[string]string {
	hashes := make(map[string]string, len(algorithms))

	file, err := os.Open(path)
	if err != nil {
		logger.Warnf("Failed to open file for hashing %s: %v", path, err)
		return hashes
	}
	defer file.Close()

	set := NewSet(algorithms)
	if set.Enabled() {
		bufferPool := &hashBufferSmallPool
		if info, statErr := file.Stat(); statErr == nil && info.Size() >= hashLargeBufferThreshold {
			bufferPool = &hashBufferLargePool
		}
		bufferPtr := bufferPool.Get().(*[]byte)
		buffer := *bufferPtr
		for {
			n, readErr := file.Read(buffer)
			if n > 0 {
				set.Write(buffer[:n])
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

	return set.Sum()
}
