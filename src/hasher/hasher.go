package hasher

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"fmt"
	"hash"
	"io"
	"os"

	"github.com/glaslos/ssdeep"
	"safnari/logger"
)

func ComputeHashes(path string, algorithms []string) map[string]string {
	hashes := make(map[string]string)

	file, err := os.Open(path)
	if err != nil {
		logger.Warnf("Failed to open file for hashing %s: %v", path, err)
		return hashes
	}
	defer file.Close()

	hashers := make(map[string]hash.Hash)
	writers := []io.Writer{}
	needSSDeep := false

	for _, algo := range algorithms {
		switch algo {
		case "md5":
			h := md5.New()
			hashers["md5"] = h
			writers = append(writers, h)
		case "sha1":
			h := sha1.New()
			hashers["sha1"] = h
			writers = append(writers, h)
		case "sha256":
			h := sha256.New()
			hashers["sha256"] = h
			writers = append(writers, h)
		case "ssdeep":
			needSSDeep = true
		default:
			logger.Warnf("Unsupported hash algorithm: %s", algo)
		}
	}

	if len(writers) > 0 {
		if _, err := io.Copy(io.MultiWriter(writers...), file); err != nil {
			logger.Warnf("Failed to compute hashes for %s: %v", path, err)
		}
	}

	for algo, h := range hashers {
		hashes[algo] = fmt.Sprintf("%x", h.Sum(nil))
	}

	if needSSDeep {
		if _, err := file.Seek(0, io.SeekStart); err == nil {
			if hash, err := ssdeep.FuzzyFile(file); err == nil {
				hashes["ssdeep"] = hash
			}
		}
	}

	return hashes
}
