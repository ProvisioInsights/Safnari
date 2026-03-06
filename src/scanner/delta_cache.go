package scanner

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"

	"safnari/config"

	"github.com/FastFilter/xorfilter"
	"github.com/cespare/xxhash/v2"
	"lukechampine.com/blake3"
)

const (
	deltaCacheManifestName = "manifest.json"
	deltaCacheChunkSize    = 256 * 1024
)

type deltaCacheManifest struct {
	Version int               `json:"version"`
	Entries map[string]string `json:"entries"`
}

type deltaCachedFile struct {
	Key               string              `json:"key"`
	Path              string              `json:"path"`
	ConfigFingerprint string              `json:"config_fingerprint"`
	ChunkSize         int                 `json:"chunk_size"`
	ReadLimit         int64               `json:"read_limit"`
	ChunkHashes       []string            `json:"chunk_hashes"`
	Chunks            []deltaCachedChunk  `json:"chunks,omitempty"`
	SearchHits        map[string]int      `json:"search_hits,omitempty"`
	SensitiveMatches  map[string][]string `json:"sensitive_matches,omitempty"`
	SensitiveCounts   map[string]int      `json:"sensitive_counts,omitempty"`
	FuzzyHashes       map[string]string   `json:"fuzzy_hashes,omitempty"`
}

type deltaCachedChunk struct {
	SearchCounts     map[string]int             `json:"search_counts,omitempty"`
	SensitiveMatches map[string][]deltaValueRun `json:"sensitive_matches,omitempty"`
}

type deltaValueRun struct {
	Value string `json:"value"`
	Count int    `json:"count"`
}

// DeltaChunkCache persists chunk fingerprints and content-analysis results for
// delta-scan reuse. It keeps an approximate membership filter in front of the
// manifest so negative lookups stay cheap as the cache grows.
type DeltaChunkCache struct {
	dir           string
	maxBytes      int64
	mu            sync.Mutex
	manifest      deltaCacheManifest
	manifestDirty bool
	filter        *xorfilter.BinaryFuse8
	filterKeys    []uint64
	filterDirty   bool
}

func openDeltaChunkCache(cfg *config.Config) (*DeltaChunkCache, error) {
	if cfg == nil || !cfg.DeltaScan || deltaCacheMode(cfg) != "chunk" {
		return nil, nil
	}
	dir := normalizeChunkCacheDir(cfg.DeltaCacheDir)
	if dir == "" {
		return nil, nil
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, err
	}
	cache := &DeltaChunkCache{
		dir:      dir,
		maxBytes: cfg.DeltaCacheMaxBytes,
		manifest: deltaCacheManifest{
			Version: 1,
			Entries: make(map[string]string),
		},
	}
	if err := cache.loadManifest(); err != nil {
		return nil, err
	}
	return cache, nil
}

func deltaCacheMode(cfg *config.Config) string {
	if cfg == nil {
		return ""
	}
	mode := strings.ToLower(strings.TrimSpace(cfg.DeltaCacheMode))
	if mode == "" {
		return "chunk"
	}
	return mode
}

func (c *DeltaChunkCache) Close() error {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.manifestDirty {
		return nil
	}
	return c.saveManifestLocked()
}

func (c *DeltaChunkCache) Load(path string, fingerprint string, readLimit int64) (*deltaCachedFile, bool, error) {
	if c == nil {
		return nil, false, nil
	}
	key := deltaCacheKey(path)
	keyUint := xxhash.Sum64String(key)

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.filterDirty {
		c.rebuildFilterLocked()
	}
	if c.filter != nil && !c.filter.Contains(keyUint) {
		return nil, false, nil
	}
	name, ok := c.manifest.Entries[key]
	if !ok {
		return nil, false, nil
	}
	data, err := os.ReadFile(filepath.Join(c.dir, name))
	if err != nil {
		return nil, false, err
	}
	var entry deltaCachedFile
	if err := json.Unmarshal(data, &entry); err != nil {
		return nil, false, err
	}
	if entry.ConfigFingerprint != fingerprint || entry.ReadLimit != readLimit {
		return nil, false, nil
	}
	return &entry, true, nil
}

func (c *DeltaChunkCache) Store(path string, entry *deltaCachedFile) error {
	if c == nil || entry == nil {
		return nil
	}
	key := deltaCacheKey(path)
	entry.Key = key
	entry.Path = path
	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	name := key + ".json"
	target := filepath.Join(c.dir, name)
	tmp := target + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	if err := os.Rename(tmp, target); err != nil {
		return err
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	c.manifest.Entries[key] = name
	c.manifestDirty = true
	c.filterDirty = true
	if err := c.evictLocked(); err != nil {
		return err
	}
	return nil
}

func (c *DeltaChunkCache) loadManifest() error {
	path := filepath.Join(c.dir, deltaCacheManifestName)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if err := json.Unmarshal(data, &c.manifest); err != nil {
		return err
	}
	c.filterDirty = true
	return nil
}

func (c *DeltaChunkCache) saveManifestLocked() error {
	data, err := json.Marshal(&c.manifest)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(c.dir, deltaCacheManifestName), data, 0600); err != nil {
		return err
	}
	c.manifestDirty = false
	return nil
}

func (c *DeltaChunkCache) rebuildFilterLocked() {
	if len(c.manifest.Entries) == 0 {
		c.filter = nil
		c.filterKeys = nil
		c.filterDirty = false
		return
	}
	keys := make([]uint64, 0, len(c.manifest.Entries))
	for key := range c.manifest.Entries {
		keys = append(keys, xxhash.Sum64String(key))
	}
	filter, err := xorfilter.PopulateBinaryFuse8(keys)
	if err != nil {
		c.filter = nil
		c.filterKeys = nil
		c.filterDirty = false
		return
	}
	c.filter = filter
	c.filterKeys = keys
	c.filterDirty = false
}

func (c *DeltaChunkCache) evictLocked() error {
	if c.maxBytes <= 0 {
		return nil
	}
	type entryInfo struct {
		key     string
		path    string
		modTime int64
		size    int64
	}
	var infos []entryInfo
	var total int64
	for key, name := range c.manifest.Entries {
		fullPath := filepath.Join(c.dir, name)
		info, err := os.Stat(fullPath)
		if err != nil {
			delete(c.manifest.Entries, key)
			c.manifestDirty = true
			c.filterDirty = true
			continue
		}
		total += info.Size()
		infos = append(infos, entryInfo{
			key:     key,
			path:    fullPath,
			modTime: info.ModTime().UnixNano(),
			size:    info.Size(),
		})
	}
	if total <= c.maxBytes {
		return nil
	}
	sort.Slice(infos, func(i, j int) bool {
		if infos[i].modTime == infos[j].modTime {
			return infos[i].key < infos[j].key
		}
		return infos[i].modTime < infos[j].modTime
	})
	for _, info := range infos {
		if total <= c.maxBytes {
			break
		}
		if err := os.Remove(info.path); err != nil && !os.IsNotExist(err) {
			return err
		}
		delete(c.manifest.Entries, info.key)
		c.manifestDirty = true
		c.filterDirty = true
		total -= info.size
	}
	return nil
}

func deltaCacheKey(path string) string {
	cleaned := filepath.Clean(path)
	sum := sha256.Sum256([]byte(cleaned))
	return hex.EncodeToString(sum[:])
}

func deltaCacheFingerprint(cfg *config.Config, patterns map[string]*regexp.Regexp) string {
	payload := struct {
		CacheFormatVersion   int      `json:"cache_format_version"`
		SearchTerms          []string `json:"search_terms"`
		SensitiveEngine      string   `json:"sensitive_engine"`
		SensitiveLongtail    string   `json:"sensitive_longtail"`
		SensitiveMatchMode   string   `json:"sensitive_match_mode"`
		SensitiveWindowBytes int      `json:"sensitive_window_bytes"`
		SensitiveMaxPerType  int      `json:"sensitive_max_per_type"`
		SensitiveMaxTotal    int      `json:"sensitive_max_total"`
		ContentScanMaxBytes  int64    `json:"content_scan_max_bytes"`
		PatternDefs          []string `json:"pattern_defs"`
	}{
		CacheFormatVersion:   3,
		SearchTerms:          append([]string(nil), normalizeSearchTerms(cfg.SearchTerms)...),
		SensitiveEngine:      cfg.SensitiveEngine,
		SensitiveLongtail:    cfg.SensitiveLongtail,
		SensitiveMatchMode:   sensitiveMatchMode(cfg),
		SensitiveWindowBytes: cfg.SensitiveWindowBytes,
		SensitiveMaxPerType:  cfg.SensitiveMaxPerType,
		SensitiveMaxTotal:    cfg.SensitiveMaxTotal,
		ContentScanMaxBytes:  cfg.ContentScanMaxBytes,
		PatternDefs:          sortedPatternDefs(patterns),
	}
	data, _ := json.Marshal(payload)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func sortedPatternNames(patterns map[string]*regexp.Regexp) []string {
	names := make([]string, 0, len(patterns))
	for name := range patterns {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func sortedPatternDefs(patterns map[string]*regexp.Regexp) []string {
	defs := make([]string, 0, len(patterns))
	for name, pattern := range patterns {
		def := ""
		if pattern != nil {
			def = pattern.String()
		}
		defs = append(defs, name+"="+def)
	}
	sort.Strings(defs)
	return defs
}

type deltaChunkHasher struct {
	chunkSize int
	limit     int64
	consumed  int64
	chunks    []string
	buffer    []byte
}

func newDeltaChunkHasher(limit int64) *deltaChunkHasher {
	return &deltaChunkHasher{
		chunkSize: deltaCacheChunkSize,
		limit:     limit,
	}
}

func (c *deltaChunkHasher) Consume(chunk []byte, _ int64) error {
	if c == nil {
		return nil
	}
	if c.limit > 0 {
		remaining := c.limit - c.consumed
		if remaining <= 0 {
			return nil
		}
		if int64(len(chunk)) > remaining {
			chunk = chunk[:remaining]
		}
	}
	if len(chunk) == 0 {
		return nil
	}
	c.buffer = append(c.buffer, chunk...)
	c.consumed += int64(len(chunk))
	for len(c.buffer) >= c.chunkSize {
		c.emitChunk(c.buffer[:c.chunkSize])
		c.buffer = c.buffer[c.chunkSize:]
	}
	return nil
}

func (c *deltaChunkHasher) Finalize() error {
	if c == nil {
		return nil
	}
	if len(c.buffer) > 0 {
		c.emitChunk(c.buffer)
		c.buffer = nil
	}
	return nil
}

func (c *deltaChunkHasher) emitChunk(chunk []byte) {
	h := blake3.New(32, nil)
	_, _ = h.Write(chunk)
	c.chunks = append(c.chunks, hex.EncodeToString(h.Sum(nil)))
}

func matchAllCachedChunks(current []string, cached []string) bool {
	if len(current) != len(cached) {
		return false
	}
	if len(current) == 0 {
		return true
	}
	for i := range current {
		if current[i] != cached[i] {
			return false
		}
	}
	return true
}
