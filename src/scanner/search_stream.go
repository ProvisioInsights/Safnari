package scanner

import (
	"io"
	"os"
	"strings"
)

func countSearchTermsStream(path string, terms []string, chunkSize int, maxSize int64) (map[string]int, error) {
	normalized := normalizeSearchTerms(terms)
	if len(normalized) == 0 {
		return nil, nil
	}
	if chunkSize <= 0 {
		chunkSize = 256 * 1024
	}
	maxSize = clampContentMaxSize(maxSize)

	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	counter := newStreamAhoCounter(normalized)

	buffer := make([]byte, chunkSize)
	var consumed int64
	for {
		n, readErr := file.Read(buffer)
		if n > 0 {
			chunk := buffer[:n]
			if maxSize > 0 && consumed+int64(n) > maxSize {
				allowed := int(maxSize - consumed)
				if allowed < 0 {
					allowed = 0
				}
				chunk = chunk[:allowed]
				readErr = io.EOF
			}
			counter.Consume(chunk)
			consumed += int64(len(chunk))
		}
		if readErr != nil {
			if readErr == io.EOF {
				break
			}
			return nil, readErr
		}
	}

	return counter.Results(), nil
}

func normalizeSearchTerms(terms []string) []string {
	if len(terms) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(terms))
	normalized := make([]string, 0, len(terms))
	for _, term := range terms {
		term = strings.TrimSpace(term)
		if term == "" {
			continue
		}
		if _, ok := seen[term]; ok {
			continue
		}
		seen[term] = struct{}{}
		normalized = append(normalized, term)
	}
	return normalized
}

func shouldUseStreamSearchCounter(contentReadMode string, hasCachedContent bool, termCount int) bool {
	if hasCachedContent {
		return false
	}
	if termCount == 0 {
		return false
	}
	return strings.ToLower(strings.TrimSpace(contentReadMode)) == "stream"
}
