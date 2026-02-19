package scanner

import (
	"io"
	"os"
	"regexp"
	"strings"

	"safnari/scanner/sensitive"
)

func shouldUseDeterministicStreamSensitiveScan(
	contentReadMode string,
	engine string,
	longtail string,
	criticalPatternNames []string,
	hasSearchTerms bool,
) bool {
	if len(criticalPatternNames) == 0 {
		return false
	}
	if hasSearchTerms {
		return false
	}
	if strings.ToLower(strings.TrimSpace(contentReadMode)) != "stream" {
		return false
	}
	engine = strings.ToLower(strings.TrimSpace(engine))
	if engine != "auto" && engine != "deterministic" && engine != "hybrid" {
		return false
	}
	return strings.ToLower(strings.TrimSpace(longtail)) == "off"
}

func scanSensitiveDataDeterministicStream(
	path string,
	patterns map[string]*regexp.Regexp,
	patternNames []string,
	maxPerType int,
	maxTotal int,
	streamChunkSize int,
	streamOverlapBytes int,
	maxSize int64,
) (map[string][]string, map[string]int, error) {
	if len(patterns) == 0 || len(patternNames) == 0 {
		return nil, nil, nil
	}
	maxSize = clampContentMaxSize(maxSize)
	if streamChunkSize <= 0 {
		streamChunkSize = 256 * 1024
	}
	if streamOverlapBytes < 0 {
		streamOverlapBytes = 0
	}
	if streamOverlapBytes >= streamChunkSize {
		streamOverlapBytes = streamChunkSize / 2
	}

	file, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer file.Close()

	if info, err := file.Stat(); err == nil && maxSize > 0 && info.Size() > maxSize {
		return nil, nil, nil
	}

	buffer := make([]byte, streamChunkSize)
	carry := make([]byte, 0, streamOverlapBytes)
	spanSeen := make(map[string]map[uint64]struct{}, len(patternNames))
	matches := make(map[string][]string, len(patternNames))
	counts := make(map[string]int, len(patternNames))

	var totalCount int
	var consumed int64
	totalLimited := maxTotal > 0
	perTypeLimited := maxPerType > 0

	for {
		n, readErr := file.Read(buffer)
		if n > 0 {
			chunk := buffer[:n]
			window := chunk
			if len(carry) > 0 {
				window = make([]byte, len(carry)+len(chunk))
				copy(window, carry)
				copy(window[len(carry):], chunk)
			}

			windowStart := consumed - int64(len(carry))
			chunkMatches := sensitive.ScanDeterministicMatches(window, patternNames, 0, 0)
			carryLimit := len(carry)
			for _, m := range chunkMatches {
				if totalLimited && totalCount >= maxTotal {
					break
				}
				if m.End <= carryLimit {
					continue
				}
				if perTypeLimited && counts[m.Pattern] >= maxPerType {
					continue
				}

				absStart := int(windowStart) + m.Start
				absEnd := int(windowStart) + m.End
				if absStart < 0 || absEnd <= absStart {
					continue
				}
				key := uint64(uint32(absStart))<<32 | uint64(uint32(absEnd))
				if _, ok := spanSeen[m.Pattern]; !ok {
					spanSeen[m.Pattern] = make(map[uint64]struct{}, 8)
				}
				if _, exists := spanSeen[m.Pattern][key]; exists {
					continue
				}
				spanSeen[m.Pattern][key] = struct{}{}
				matches[m.Pattern] = append(matches[m.Pattern], m.Value)
				counts[m.Pattern]++
				totalCount++
			}

			consumed += int64(n)
			if streamOverlapBytes > 0 {
				if len(window) <= streamOverlapBytes {
					carry = append(carry[:0], window...)
				} else {
					carry = append(carry[:0], window[len(window)-streamOverlapBytes:]...)
				}
			}

			if totalLimited && totalCount >= maxTotal {
				break
			}
			if perTypeLimited && allPerTypeLimitsReached(counts, patternNames, maxPerType) {
				break
			}
		}

		if readErr != nil {
			if readErr == io.EOF {
				break
			}
			return nil, nil, readErr
		}
	}

	if len(matches) == 0 {
		return nil, nil, nil
	}
	return matches, counts, nil
}

func allPerTypeLimitsReached(counts map[string]int, patternNames []string, maxPerType int) bool {
	if maxPerType <= 0 {
		return false
	}
	if len(patternNames) == 0 {
		return false
	}
	for _, pattern := range patternNames {
		if counts[pattern] < maxPerType {
			return false
		}
	}
	return true
}
