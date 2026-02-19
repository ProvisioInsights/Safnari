package scanner

import (
	"io"
	"os"
	"strings"
)

type streamTermCounter struct {
	term    string
	pattern []byte
	prefix  []int
	matched int
	count   int
}

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

	if info, err := file.Stat(); err == nil && maxSize > 0 && info.Size() > maxSize {
		return nil, nil
	}

	counters := make([]streamTermCounter, 0, len(normalized))
	for _, term := range normalized {
		pattern := []byte(term)
		if len(pattern) == 0 {
			continue
		}
		counters = append(counters, streamTermCounter{
			term:    term,
			pattern: pattern,
			prefix:  buildKMPPrefix(pattern),
		})
	}
	if len(counters) == 0 {
		return nil, nil
	}

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
			for _, b := range chunk {
				for i := range counters {
					c := &counters[i]
					for c.matched > 0 && b != c.pattern[c.matched] {
						c.matched = c.prefix[c.matched-1]
					}
					if b == c.pattern[c.matched] {
						c.matched++
					}
					if c.matched == len(c.pattern) {
						c.count++
						// bytes.Count semantics are non-overlapping.
						c.matched = 0
					}
				}
			}
			consumed += int64(len(chunk))
		}
		if readErr != nil {
			if readErr == io.EOF {
				break
			}
			return nil, readErr
		}
	}

	var hits map[string]int
	for _, c := range counters {
		if c.count <= 0 {
			continue
		}
		if hits == nil {
			hits = make(map[string]int, len(counters))
		}
		hits[c.term] = c.count
	}
	return hits, nil
}

func buildKMPPrefix(pattern []byte) []int {
	prefix := make([]int, len(pattern))
	var j int
	for i := 1; i < len(pattern); i++ {
		for j > 0 && pattern[i] != pattern[j] {
			j = prefix[j-1]
		}
		if pattern[i] == pattern[j] {
			j++
		}
		prefix[i] = j
	}
	return prefix
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
