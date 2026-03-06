package scanner

import (
	"regexp"
	"sort"

	"safnari/config"
	"safnari/scanner/sensitive"
)

func runContentPipelineWithDeltaCache(
	fc *FileContext,
	source *ChunkSource,
	contentLimit int64,
	hashConsumer *streamHashConsumer,
	fuzzyConsumer *streamFuzzyConsumer,
	searchEnabled bool,
	sensitiveEnabled bool,
) (*contentAnalysisResults, error) {
	if fc == nil || fc.deltaCache == nil || source == nil {
		return nil, nil
	}

	fingerprint := deltaCacheFingerprint(fc.Cfg, fc.SensitivePatterns)
	analysisLimit := contentLimit
	chunkHasher := newDeltaChunkHasher(analysisLimit)
	consumers := []ChunkConsumer{chunkHasher}
	if hashConsumer != nil {
		consumers = append(consumers, hashConsumer)
	}
	if fuzzyConsumer != nil {
		consumers = append(consumers, fuzzyConsumer)
	}

	pipelineLimit := analysisLimit
	if hashConsumer != nil || fuzzyConsumer != nil {
		pipelineLimit = 0
	}
	pipeline := &ScanPipeline{
		source:    source,
		consumers: consumers,
		limit:     pipelineLimit,
	}
	if err := pipeline.Run(); err != nil {
		return nil, err
	}

	results := &contentAnalysisResults{}
	if hashConsumer != nil {
		results.hashes = hashConsumer.results
	}
	if fuzzyConsumer != nil && fuzzyConsumer.hash != "" {
		results.fuzzyHashes = map[string]string{"tlsh": fuzzyConsumer.hash}
	}

	cached, cachedOK, err := fc.deltaCache.Load(fc.Path, fingerprint, analysisLimit)
	if err != nil {
		cachedOK = false
	}

	if cachedOK && matchAllCachedChunks(chunkHasher.chunks, cached.ChunkHashes) {
		results.searchHits = cloneIntMap(cached.SearchHits)
		results.sensitiveMatches = cloneStringSliceMap(cached.SensitiveMatches)
		results.sensitiveMatchCount = cloneIntMap(cached.SensitiveCounts)
		if len(results.fuzzyHashes) == 0 {
			results.fuzzyHashes = cloneStringMap(cached.FuzzyHashes)
		}
		return results, nil
	}

	cacheableSensitive := shouldChunkCacheSensitive(fc.Cfg, fc.SensitivePatterns)
	entry := &deltaCachedFile{
		ConfigFingerprint: fingerprint,
		ChunkSize:         deltaCacheChunkSize,
		ReadLimit:         analysisLimit,
		ChunkHashes:       append([]string(nil), chunkHasher.chunks...),
		FuzzyHashes:       cloneStringMap(results.fuzzyHashes),
	}

	if searchEnabled || cacheableSensitive {
		chunks, err := buildDeltaCachedChunks(
			source,
			analysisSizeForLimit(fc, analysisLimit),
			chunkHasher.chunks,
			cached,
			fc.Cfg,
			fc.Cfg.SearchTerms,
			fc.SensitivePatterns,
			searchEnabled,
			cacheableSensitive,
		)
		if err != nil {
			return nil, err
		}
		entry.Chunks = chunks
		if searchEnabled {
			results.searchHits = aggregateSearchChunkResults(chunks)
			entry.SearchHits = cloneIntMap(results.searchHits)
		}
		if cacheableSensitive {
			results.sensitiveMatches, results.sensitiveMatchCount = aggregateSensitiveChunkResults(chunks, fc.Cfg)
			entry.SensitiveMatches = cloneStringSliceMap(results.sensitiveMatches)
			entry.SensitiveCounts = cloneIntMap(results.sensitiveMatchCount)
		}
	}

	if sensitiveEnabled && !cacheableSensitive {
		patternNames := make([]string, 0, len(fc.SensitivePatterns))
		for name := range fc.SensitivePatterns {
			patternNames = append(patternNames, name)
		}
		sort.Strings(patternNames)
		sensitiveConsumer := newStreamSensitiveConsumer(fc.Cfg, fc.SensitivePatterns, patternNames, contentLimit)
		fallback := &ScanPipeline{
			source:    source,
			consumers: []ChunkConsumer{sensitiveConsumer},
			limit:     contentLimit,
		}
		if err := fallback.Run(); err != nil {
			return nil, err
		}
		results.sensitiveMatches = sensitiveConsumer.matches
		results.sensitiveMatchCount = sensitiveConsumer.counts
		entry.SensitiveMatches = cloneStringSliceMap(results.sensitiveMatches)
		entry.SensitiveCounts = cloneIntMap(results.sensitiveMatchCount)
	}

	_ = fc.deltaCache.Store(fc.Path, entry)
	return results, nil
}

func buildDeltaCachedChunks(
	source *ChunkSource,
	analysisSize int64,
	currentHashes []string,
	cached *deltaCachedFile,
	cfg *config.Config,
	searchTerms []string,
	patterns map[string]*regexp.Regexp,
	searchEnabled bool,
	sensitiveEnabled bool,
) ([]deltaCachedChunk, error) {
	if len(currentHashes) == 0 {
		return nil, nil
	}
	chunks := make([]deltaCachedChunk, len(currentHashes))
	patternNames := sortedPatternNames(patterns)
	for i := range currentHashes {
		if canReuseDeltaChunk(cached, currentHashes, i) {
			chunks[i] = cloneDeltaCachedChunk(cached.Chunks[i])
			continue
		}
		chunk, err := analyzeDeltaChunk(source, analysisSize, i, cfg, searchTerms, patternNames, searchEnabled, sensitiveEnabled)
		if err != nil {
			return nil, err
		}
		chunks[i] = chunk
	}
	return chunks, nil
}

func analyzeDeltaChunk(
	source *ChunkSource,
	analysisSize int64,
	index int,
	cfg *config.Config,
	searchTerms []string,
	patternNames []string,
	searchEnabled bool,
	sensitiveEnabled bool,
) (deltaCachedChunk, error) {
	var chunk deltaCachedChunk
	if source == nil || analysisSize <= 0 {
		return chunk, nil
	}
	chunkStart := int64(index * deltaCacheChunkSize)
	if chunkStart >= analysisSize {
		return chunk, nil
	}
	primaryEnd := minInt64(chunkStart+deltaCacheChunkSize, analysisSize)
	windowStart := maxInt64(0, chunkStart-deltaCacheChunkSize)
	windowEnd := minInt64(primaryEnd+deltaCacheChunkSize, analysisSize)
	window, err := source.ReadRange(windowStart, windowEnd-windowStart)
	if err != nil {
		return chunk, err
	}
	primaryStartInWindow := int(chunkStart - windowStart)
	primaryLen := int(primaryEnd - chunkStart)
	primaryEndInWindow := primaryStartInWindow + primaryLen
	if searchEnabled {
		chunk.SearchCounts = collectSearchChunkCounts(window, searchTerms, primaryStartInWindow, primaryEndInWindow)
	}
	if sensitiveEnabled {
		sensitiveWindow := window[:primaryEndInWindow]
		chunk.SensitiveMatches = collectCriticalSensitiveChunk(sensitiveWindow, patternNames, primaryStartInWindow, cfg)
	}
	return chunk, nil
}

func collectSearchChunkCounts(content []byte, terms []string, primaryStart, primaryEnd int) map[string]int {
	if primaryEnd <= primaryStart || len(content) == 0 {
		return nil
	}
	terms = normalizeSearchTerms(terms)
	if len(terms) == 0 {
		return nil
	}
	matcher := newStreamAhoMatcher(terms)
	if matcher == nil || len(matcher.terms) == 0 {
		return nil
	}
	counts := make(map[string]int, len(terms))
	matcher.Consume(content, func(index int, start, end int64) {
		if start < int64(primaryStart) || start >= int64(primaryEnd) {
			return
		}
		counts[matcher.terms[index]]++
	})
	if len(counts) == 0 {
		return nil
	}
	return counts
}

func collectCriticalSensitiveChunk(content []byte, patternNames []string, carryLen int, cfg *config.Config) map[string][]deltaValueRun {
	if carryLen < 0 || len(content) == 0 || len(patternNames) == 0 {
		return nil
	}
	var out map[string][]deltaValueRun
	counts := make(map[string]int, len(patternNames))
	total := 0
	sensitive.ScanDeterministicVisit(content, patternNames, nil, func(pattern string, start, end int) bool {
		if end <= carryLen {
			return true
		}
		if remainingSensitivePerTypeLimit(cfg, pattern, counts) == 0 {
			return true
		}
		if cfg != nil && cfg.SensitiveMaxTotal > 0 && total >= cfg.SensitiveMaxTotal {
			return false
		}
		if out == nil {
			out = make(map[string][]deltaValueRun, len(patternNames))
		}
		value := string(content[start:end])
		runs := out[pattern]
		if n := len(runs); n > 0 && runs[n-1].Value == value {
			runs[n-1].Count++
			out[pattern] = runs
		} else {
			out[pattern] = append(runs, deltaValueRun{Value: value, Count: 1})
		}
		counts[pattern]++
		total++
		if sensitiveCollectionSaturated(cfg, patternNames, counts, total) {
			return false
		}
		return true
	})
	if len(out) == 0 {
		return nil
	}
	return out
}

func aggregateSearchChunkResults(chunks []deltaCachedChunk) map[string]int {
	if len(chunks) == 0 {
		return nil
	}
	counts := make(map[string]int)
	for _, chunk := range chunks {
		if len(chunk.SearchCounts) == 0 {
			continue
		}
		for term, count := range chunk.SearchCounts {
			counts[term] += count
		}
	}
	if len(counts) == 0 {
		return nil
	}
	return counts
}

func aggregateSensitiveChunkResults(chunks []deltaCachedChunk, cfg *config.Config) (map[string][]string, map[string]int) {
	if len(chunks) == 0 {
		return nil, nil
	}
	var (
		totalLimit   int
		perTypeLimit int
	)
	if cfg != nil {
		totalLimit = cfg.SensitiveMaxTotal
		perTypeLimit = effectiveSensitivePerTypeLimit(cfg)
	}
	matches := make(map[string][]string)
	counts := make(map[string]int)
	total := 0
	for _, chunk := range chunks {
		if len(chunk.SensitiveMatches) == 0 {
			continue
		}
		patternNames := make([]string, 0, len(chunk.SensitiveMatches))
		for pattern := range chunk.SensitiveMatches {
			patternNames = append(patternNames, pattern)
		}
		sort.Strings(patternNames)
		for _, pattern := range patternNames {
			for _, run := range chunk.SensitiveMatches[pattern] {
				if run.Count <= 0 {
					continue
				}
				remaining := run.Count
				for remaining > 0 {
					if totalLimit > 0 && total >= totalLimit {
						if len(matches) == 0 {
							return nil, nil
						}
						return matches, counts
					}
					if perTypeLimit > 0 && counts[pattern] >= perTypeLimit {
						break
					}
					matches[pattern] = append(matches[pattern], run.Value)
					counts[pattern]++
					total++
					remaining--
				}
			}
		}
	}
	if len(matches) == 0 {
		return nil, nil
	}
	return matches, counts
}

func allSensitivePatternsCritical(patterns map[string]*regexp.Regexp) bool {
	if len(patterns) == 0 {
		return false
	}
	for name := range patterns {
		if !sensitive.IsCriticalPattern(name) {
			return false
		}
	}
	return true
}

func shouldChunkCacheSensitive(cfg *config.Config, patterns map[string]*regexp.Regexp) bool {
	if cfg == nil || !allSensitivePatternsCritical(patterns) {
		return false
	}
	if sensitiveMatchMode(cfg) != "all" {
		return false
	}
	return true
}

func analysisSizeForLimit(fc *FileContext, limit int64) int64 {
	if fc == nil || fc.Info == nil {
		return 0
	}
	size := fc.Info.Size()
	if limit > 0 && size > limit {
		return limit
	}
	return size
}

func shouldUseDeltaChunkCacheForFile(fc *FileContext, limit int64, fullFileWork bool) bool {
	if fc == nil || fc.deltaCache == nil {
		return false
	}
	if !fullFileWork {
		return true
	}
	size := analysisSizeForLimit(fc, limit)
	if size <= 0 {
		return false
	}
	chunkCount := int((size + deltaCacheChunkSize - 1) / deltaCacheChunkSize)
	// Small changed files already incur a full-file pass for authoritative
	// hashes, so chunk-cache bookkeeping usually costs more than it saves.
	return chunkCount >= 6
}

func canReuseDeltaChunk(
	cached *deltaCachedFile,
	currentHashes []string,
	index int,
) bool {
	if cached == nil || index >= len(currentHashes) || index >= len(cached.ChunkHashes) || index >= len(cached.Chunks) {
		return false
	}
	if currentHashes[index] != cached.ChunkHashes[index] {
		return false
	}
	if index > 0 {
		if index-1 >= len(cached.ChunkHashes) || currentHashes[index-1] != cached.ChunkHashes[index-1] {
			return false
		}
	}
	if index+1 < len(currentHashes) {
		if index+1 >= len(cached.ChunkHashes) || currentHashes[index+1] != cached.ChunkHashes[index+1] {
			return false
		}
	}
	return true
}

func cloneDeltaCachedChunk(in deltaCachedChunk) deltaCachedChunk {
	return deltaCachedChunk{
		SearchCounts:     cloneIntMap(in.SearchCounts),
		SensitiveMatches: cloneDeltaValueRuns(in.SensitiveMatches),
	}
}

func cloneStringMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}

func cloneIntMap(in map[string]int) map[string]int {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]int, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}

func cloneStringSliceMap(in map[string][]string) map[string][]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string][]string, len(in))
	for key, values := range in {
		out[key] = append([]string(nil), values...)
	}
	return out
}

func cloneDeltaValueRuns(in map[string][]deltaValueRun) map[string][]deltaValueRun {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string][]deltaValueRun, len(in))
	for key, values := range in {
		out[key] = append([]deltaValueRun(nil), values...)
	}
	return out
}

func minInt64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

func maxInt64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}
