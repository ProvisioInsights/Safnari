package scanner

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"safnari/config"
	"safnari/hasher"
	"safnari/scanner/sensitive"

	"github.com/glaslos/tlsh"
)

// ChunkConsumer is the streaming unit of work attached to a ScanPipeline.
type ChunkConsumer interface {
	Consume(chunk []byte, offset int64) error
	Finalize() error
}

// ScanPipeline fans one forward-only byte stream out to multiple consumers.
type ScanPipeline struct {
	source    *ChunkSource
	consumers []ChunkConsumer
	limit     int64
}

func (p *ScanPipeline) Run() error {
	if p == nil || p.source == nil {
		return nil
	}
	if err := p.source.Scan(p.limit, func(chunk []byte, offset int64) error {
		for _, consumer := range p.consumers {
			if err := consumer.Consume(chunk, offset); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		return err
	}
	for _, consumer := range p.consumers {
		if err := consumer.Finalize(); err != nil {
			return err
		}
	}
	return nil
}

type streamHashConsumer struct {
	set     *hasher.Set
	results map[string]string
}

func newStreamHashConsumer(algorithms []string) *streamHashConsumer {
	return &streamHashConsumer{set: hasher.NewSet(algorithms)}
}

func (c *streamHashConsumer) Consume(chunk []byte, _ int64) error {
	if c == nil || c.set == nil {
		return nil
	}
	c.set.Write(chunk)
	return nil
}

func (c *streamHashConsumer) Finalize() error {
	if c == nil || c.set == nil || !c.set.Enabled() {
		return nil
	}
	c.results = c.set.Sum()
	return nil
}

type streamFuzzyConsumer struct {
	tlsh *tlsh.TLSH
	hash string
}

func newStreamFuzzyConsumer() *streamFuzzyConsumer {
	return &streamFuzzyConsumer{tlsh: tlsh.New()}
}

func (c *streamFuzzyConsumer) Consume(chunk []byte, _ int64) error {
	if c == nil || c.tlsh == nil {
		return nil
	}
	_, err := c.tlsh.Write(chunk)
	return err
}

func (c *streamFuzzyConsumer) Finalize() error {
	if c == nil || c.tlsh == nil {
		return nil
	}
	sum := c.tlsh.Sum(nil)
	if len(sum) == 0 {
		return nil
	}
	allZero := true
	for _, b := range sum {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return nil
	}
	c.hash = c.tlsh.String()
	return nil
}

type streamSearchConsumer struct {
	limit    int64
	consumed int64
	counter  *streamAhoCounter
	results  map[string]int
}

func newStreamSearchConsumer(terms []string, limit int64) *streamSearchConsumer {
	return &streamSearchConsumer{
		limit:   limit,
		counter: newStreamAhoCounter(terms),
	}
}

func (c *streamSearchConsumer) Consume(chunk []byte, _ int64) error {
	if c == nil || c.counter == nil || len(chunk) == 0 {
		return nil
	}
	chunk = truncateStreamChunk(chunk, c.limit, c.consumed)
	if len(chunk) == 0 {
		return nil
	}
	c.counter.Consume(chunk)
	c.consumed += int64(len(chunk))
	return nil
}

func (c *streamSearchConsumer) Finalize() error {
	if c == nil || c.counter == nil {
		return nil
	}
	c.results = c.counter.Results()
	return nil
}

type streamSensitiveConsumer struct {
	cfg          *config.Config
	patterns     map[string]*regexp.Regexp
	patternNames []string

	limit    int64
	consumed int64

	criticalPatternNames []string
	carry                []byte
	window               []byte
	spanSeen             map[string]map[uint64]struct{}
	matches              map[string][]string
	counts               map[string]int
	totalCount           int
	saturated            bool

	regexBuffer []byte
}

func newStreamSensitiveConsumer(
	cfg *config.Config,
	patterns map[string]*regexp.Regexp,
	patternNames []string,
	limit int64,
) *streamSensitiveConsumer {
	critical := filterCriticalPatternNames(patternNames, patterns)
	return &streamSensitiveConsumer{
		cfg:                  cfg,
		patterns:             patterns,
		patternNames:         patternNames,
		limit:                limit,
		criticalPatternNames: critical,
		spanSeen:             make(map[string]map[uint64]struct{}, len(patternNames)),
	}
}

func (c *streamSensitiveConsumer) Consume(chunk []byte, offset int64) error {
	if c == nil || c.saturated || len(chunk) == 0 {
		return nil
	}
	chunk = truncateStreamChunk(chunk, c.limit, c.consumed)
	if len(chunk) == 0 {
		return nil
	}
	if len(c.criticalPatternNames) > 0 {
		if err := c.consumeDeterministic(chunk, offset); err != nil {
			return err
		}
	}
	if !c.saturated && c.needsRegexBuffer() {
		c.regexBuffer = append(c.regexBuffer, chunk...)
	}
	c.consumed += int64(len(chunk))
	return nil
}

func (c *streamSensitiveConsumer) consumeDeterministic(chunk []byte, offset int64) error {
	window := chunk
	if len(c.carry) > 0 {
		c.window = append(c.window[:0], c.carry...)
		c.window = append(c.window, chunk...)
		window = c.window
	}
	windowStart := offset - int64(len(c.carry))
	carryLimit := len(c.carry)
	if sensitiveCollectionSaturated(c.cfg, c.patternNames, c.counts, c.totalCount) {
		c.saturated = true
		return nil
	}
	activeCritical := activeSensitivePatternNames(c.cfg, c.criticalPatternNames, c.counts)
	if len(activeCritical) == 0 {
		return c.updateCarry(window)
	}

	sensitive.ScanDeterministicVisit(
		window,
		activeCritical,
		nil,
		func(pattern string, start, end int) bool {
			if end <= carryLimit {
				return true
			}
			absStart := int(windowStart) + start
			absEnd := int(windowStart) + end
			if absStart < 0 || absEnd <= absStart {
				return true
			}
			key := uint64(uint32(absStart))<<32 | uint64(uint32(absEnd))
			if _, ok := c.spanSeen[pattern]; !ok {
				c.spanSeen[pattern] = make(map[uint64]struct{}, 8)
			}
			if _, exists := c.spanSeen[pattern][key]; exists {
				return true
			}
			if remainingSensitivePerTypeLimit(c.cfg, pattern, c.counts) == 0 {
				return true
			}
			if c.cfg != nil && c.cfg.SensitiveMaxTotal > 0 && c.totalCount >= c.cfg.SensitiveMaxTotal {
				c.saturated = true
				return false
			}
			c.spanSeen[pattern][key] = struct{}{}
			if c.matches == nil {
				c.matches = make(map[string][]string, len(c.criticalPatternNames))
			}
			if c.counts == nil {
				c.counts = make(map[string]int, len(c.patternNames))
			}
			c.matches[pattern] = append(c.matches[pattern], string(window[start:end]))
			c.counts[pattern]++
			c.totalCount++
			if sensitiveCollectionSaturated(c.cfg, c.patternNames, c.counts, c.totalCount) {
				c.saturated = true
				return false
			}
			return true
		},
	)

	return c.updateCarry(window)
}

func (c *streamSensitiveConsumer) updateCarry(window []byte) error {
	overlap := 0
	if c.cfg != nil {
		overlap = c.cfg.StreamOverlapBytes
	}
	if overlap <= 0 {
		overlap = 512
	}
	if len(window) <= overlap {
		c.carry = append(c.carry[:0], window...)
		return nil
	}
	c.carry = append(c.carry[:0], window[len(window)-overlap:]...)
	return nil
}

func (c *streamSensitiveConsumer) needsRegexBuffer() bool {
	if c == nil || c.cfg == nil {
		return false
	}
	engine := strings.ToLower(strings.TrimSpace(c.cfg.SensitiveEngine))
	longtail := strings.ToLower(strings.TrimSpace(c.cfg.SensitiveLongtail))
	if engine == "deterministic" || longtail == "off" {
		return false
	}
	for _, name := range c.patternNames {
		if !sensitive.IsCriticalPattern(name) {
			return true
		}
	}
	return false
}

func (c *streamSensitiveConsumer) Finalize() error {
	if c == nil || c.saturated || !c.needsRegexBuffer() {
		return nil
	}
	nonCritical := make([]string, 0, len(c.patternNames))
	for _, name := range c.patternNames {
		if sensitive.IsCriticalPattern(name) {
			continue
		}
		nonCritical = append(nonCritical, name)
	}
	nonCritical = activeSensitivePatternNames(c.cfg, nonCritical, c.counts)
	if len(nonCritical) == 0 {
		return nil
	}
	remainingTotal := remainingSensitiveTotalLimit(c.cfg, c.totalCount, len(activeSensitivePatternNames(c.cfg, c.patternNames, c.counts)))
	if remainingTotal == 0 && ((c.cfg != nil && c.cfg.SensitiveMaxTotal > 0) || sensitiveMatchMode(c.cfg) == "first") {
		return nil
	}
	regexMatches, regexCounts := scanForSensitiveDataAdvanced(
		c.regexBuffer,
		c.patterns,
		effectiveSensitivePerTypeLimit(c.cfg),
		remainingTotal,
		c.cfg.SensitiveEngine,
		c.cfg.SensitiveLongtail,
		c.cfg.SensitiveWindowBytes,
		nonCritical,
	)
	if len(regexMatches) == 0 {
		return nil
	}
	if c.matches == nil {
		c.matches = make(map[string][]string, len(regexMatches))
	}
	if c.counts == nil {
		c.counts = make(map[string]int, len(regexCounts))
	}
	for name, values := range regexMatches {
		c.matches[name] = append(c.matches[name], values...)
	}
	for name, count := range regexCounts {
		c.counts[name] += count
	}
	return nil
}

type contentAnalysisResults struct {
	hashes              map[string]string
	fuzzyHashes         map[string]string
	searchHits          map[string]int
	sensitiveMatches    map[string][]string
	sensitiveMatchCount map[string]int
}

func runContentPipeline(fc *FileContext) (*contentAnalysisResults, error) {
	if fc == nil || fc.Cfg == nil {
		return &contentAnalysisResults{}, nil
	}
	source, err := fc.Source()
	if err != nil {
		return nil, err
	}

	contentLimit := fc.contentScanLimit()
	fullFile := fc.FullFileProcessingAllowed()
	var consumers []ChunkConsumer

	var hashConsumer *streamHashConsumer
	if fc.Cfg.ScanFiles && fullFile && len(fc.Cfg.HashAlgorithms) > 0 {
		hashConsumer = newStreamHashConsumer(fc.Cfg.HashAlgorithms)
		if hashConsumer.set != nil && hashConsumer.set.Enabled() {
			consumers = append(consumers, hashConsumer)
		}
	}

	var fuzzyConsumer *streamFuzzyConsumer
	if fc.Cfg.FuzzyHash && fullFile && fc.Info != nil {
		size := fc.Info.Size()
		if size >= fc.Cfg.FuzzyMinSize && (fc.Cfg.FuzzyMaxSize <= 0 || size <= fc.Cfg.FuzzyMaxSize) {
			fuzzyConsumer = newStreamFuzzyConsumer()
			consumers = append(consumers, fuzzyConsumer)
		}
	}

	var searchConsumer *streamSearchConsumer
	if len(fc.Cfg.SearchTerms) > 0 && source.ShouldSearchContent() {
		searchConsumer = newStreamSearchConsumer(fc.Cfg.SearchTerms, contentLimit)
		consumers = append(consumers, searchConsumer)
		fc.markContentScan(contentLimit)
	}

	var sensitiveConsumer *streamSensitiveConsumer
	if fc.Cfg.ScanSensitive && source.ShouldSearchContent() && len(fc.SensitivePatterns) > 0 {
		patternNames := make([]string, 0, len(fc.SensitivePatterns))
		for name := range fc.SensitivePatterns {
			patternNames = append(patternNames, name)
		}
		sort.Strings(patternNames)
		sensitiveConsumer = newStreamSensitiveConsumer(fc.Cfg, fc.SensitivePatterns, patternNames, contentLimit)
		consumers = append(consumers, sensitiveConsumer)
		fc.markContentScan(contentLimit)
	}

	if len(consumers) == 0 {
		return &contentAnalysisResults{}, nil
	}

	readLimit := contentLimit
	if hashConsumer != nil || fuzzyConsumer != nil {
		readLimit = 0
	}

	if fc.deltaCache != nil &&
		source.ShouldSearchContent() &&
		(searchConsumer != nil || sensitiveConsumer != nil) &&
		shouldUseDeltaChunkCacheForFile(fc, contentLimit, hashConsumer != nil || fuzzyConsumer != nil) {
		return runContentPipelineWithDeltaCache(
			fc,
			source,
			contentLimit,
			hashConsumer,
			fuzzyConsumer,
			searchConsumer != nil,
			sensitiveConsumer != nil,
		)
	}

	pipeline := &ScanPipeline{
		source:    source,
		consumers: consumers,
		limit:     readLimit,
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
	if searchConsumer != nil {
		results.searchHits = searchConsumer.results
	}
	if sensitiveConsumer != nil {
		results.sensitiveMatches = sensitiveConsumer.matches
		results.sensitiveMatchCount = sensitiveConsumer.counts
	}
	return results, nil
}

func truncateStreamChunk(chunk []byte, limit, consumed int64) []byte {
	if limit <= 0 {
		return chunk
	}
	remaining := limit - consumed
	if remaining <= 0 {
		return nil
	}
	if int64(len(chunk)) <= remaining {
		return chunk
	}
	return chunk[:remaining]
}

func mergeSensitiveMatches(dst map[string][]string, src map[string][]string) map[string][]string {
	if len(src) == 0 {
		return dst
	}
	if dst == nil {
		dst = make(map[string][]string, len(src))
	}
	for key, values := range src {
		dst[key] = append(dst[key], values...)
	}
	return dst
}

func mergeSensitiveCounts(dst map[string]int, src map[string]int) map[string]int {
	if len(src) == 0 {
		return dst
	}
	if dst == nil {
		dst = make(map[string]int, len(src))
	}
	for key, count := range src {
		dst[key] += count
	}
	return dst
}

func unsupportedHashAlgorithms(algorithms []string) error {
	for _, algo := range algorithms {
		switch strings.ToLower(strings.TrimSpace(algo)) {
		case "", "md5", "sha1", "sha256", "blake3":
		default:
			return fmt.Errorf("unsupported streaming hash algorithm: %s", algo)
		}
	}
	return nil
}
