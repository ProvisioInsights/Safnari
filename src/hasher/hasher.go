package hasher

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"fmt"
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

	for _, algo := range algorithms {
		if hashValue := computeHash(file, algo); hashValue != "" {
			hashes[algo] = hashValue
		}
		// Reset file pointer
		file.Seek(0, io.SeekStart)
	}

	return hashes
}

func computeHash(file *os.File, algorithm string) string {
	var hashValue string
	switch algorithm {
	case "md5":
		h := md5.New()
		if _, err := io.Copy(h, file); err == nil {
			hashValue = fmt.Sprintf("%x", h.Sum(nil))
		}
	case "sha1":
		h := sha1.New()
		if _, err := io.Copy(h, file); err == nil {
			hashValue = fmt.Sprintf("%x", h.Sum(nil))
		}
	case "sha256":
		h := sha256.New()
		if _, err := io.Copy(h, file); err == nil {
			hashValue = fmt.Sprintf("%x", h.Sum(nil))
		}
	case "ssdeep":
		if hash, err := ssdeep.FuzzyFile(file); err == nil {
			hashValue = hash
		}
	default:
		logger.Warnf("Unsupported hash algorithm: %s", algorithm)
	}
	return hashValue
}
