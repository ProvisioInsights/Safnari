package scanner

import (
	"context"
	"errors"
	"os"
	"regexp"
	"sort"
	"time"

	"safnari/config"
	"safnari/fuzzy"
	"safnari/hasher"
	"safnari/logger"
	"safnari/metadata"
	"safnari/scanner/prefilter"
)

const maxContentScanBytes int64 = 10 * 1024 * 1024

type FileModule interface {
	Name() string
	Enabled(cfg *config.Config) bool
	Collect(ctx context.Context, fc *FileContext, data *FileRecord) error
}

type FileContext struct {
	Path              string
	Info              os.FileInfo
	Cfg               *config.Config
	SensitivePatterns map[string]*regexp.Regexp

	mimeLoaded  bool
	mimeType    string
	content     []byte
	contentText string
	contentErr  error
	textLoaded  bool
}

func (fc *FileContext) MimeType() string {
	if fc.mimeLoaded {
		return fc.mimeType
	}
	mimeType, err := getMimeType(fc.Path)
	if err != nil || mimeType == "" {
		mimeType = "unknown"
	}
	fc.mimeType = mimeType
	fc.mimeLoaded = true
	return fc.mimeType
}

func (fc *FileContext) ContentBytes() ([]byte, error) {
	if fc.content != nil || fc.contentErr != nil {
		return fc.content, fc.contentErr
	}
	maxSize := fc.Cfg.MaxFileSize
	if maxSize <= 0 || maxSize > maxContentScanBytes {
		maxSize = maxContentScanBytes
	}
	content, err := readFileContentWithMode(
		fc.Path,
		maxSize,
		fc.Cfg.ContentReadMode,
		fc.Cfg.MmapMinSize,
		fc.Cfg.StreamChunkSize,
		fc.Cfg.StreamOverlapBytes,
	)
	fc.content = content
	fc.contentErr = err
	return fc.content, fc.contentErr
}

func (fc *FileContext) ContentText() (string, error) {
	if fc.textLoaded {
		return fc.contentText, nil
	}
	content, err := fc.ContentBytes()
	if err != nil {
		return "", err
	}
	fc.contentText = string(content)
	fc.textLoaded = true
	return fc.contentText, nil
}

func (fc *FileContext) ShouldSearchContent() bool {
	if hasLikelyTextExtension(fc.Path) {
		return true
	}
	return shouldSearchContent(fc.MimeType(), fc.Path)
}

func buildFileModules(cfg *config.Config, patterns map[string]*regexp.Regexp) []FileModule {
	fuzzyHashers := buildFuzzyHashers(cfg)
	searchCounter := prefilter.BuildSearchCounter(cfg.SearchTerms)
	patternNames := make([]string, 0, len(patterns))
	for name := range patterns {
		patternNames = append(patternNames, name)
	}
	sort.Strings(patternNames)
	return []FileModule{
		baseModule{},
		xattrModule{},
		aclModule{},
		adsModule{},
		mimeModule{},
		hashModule{},
		metadataModule{},
		fuzzyModule{hashers: fuzzyHashers},
		sensitiveModule{patternNames: patternNames},
		searchModule{counter: searchCounter},
	}
}

type baseModule struct{}

func (m baseModule) Name() string { return "base" }

func (m baseModule) Enabled(cfg *config.Config) bool { return cfg.ScanFiles }

func (m baseModule) Collect(ctx context.Context, fc *FileContext, data *FileRecord) error {
	data.Name = fc.Info.Name()
	data.Size = fc.Info.Size()
	data.ModTime = fc.Info.ModTime().Format(time.RFC3339)

	times, err := getFileTimes(fc.Path)
	if err == nil {
		data.CreationTime = times.CreationTime
		data.AccessTime = times.AccessTime
		data.ChangeTime = times.ChangeTime
	} else {
		data.CreationTime = ""
		data.AccessTime = ""
		data.ChangeTime = ""
	}

	data.Attributes = getFileAttributes(fc.Info)
	data.Permissions = fc.Info.Mode().Perm().String()

	owner, err := getFileOwnership(fc.Path, fc.Info)
	if err == nil {
		data.Owner = owner
	} else {
		data.Owner = ""
	}

	if fileID := getFileID(fc.Path, fc.Info); fileID != "" {
		data.FileID = fileID
	}

	return nil
}

type xattrModule struct{}

func (m xattrModule) Name() string { return "xattrs" }

func (m xattrModule) Enabled(cfg *config.Config) bool { return cfg.CollectXattrs }

func (m xattrModule) Collect(ctx context.Context, fc *FileContext, data *FileRecord) error {
	xattrs, err := getXattrs(fc.Path, fc.Cfg.XattrMaxValueSize)
	if err == nil && len(xattrs) > 0 {
		data.Xattrs = xattrs
	}
	return nil
}

type aclModule struct{}

func (m aclModule) Name() string { return "acl" }

func (m aclModule) Enabled(cfg *config.Config) bool { return cfg.CollectACL }

func (m aclModule) Collect(ctx context.Context, fc *FileContext, data *FileRecord) error {
	acl, err := getFileACL(fc.Path)
	if err == nil && acl != "" {
		data.ACL = acl
	}
	return nil
}

type adsModule struct{}

func (m adsModule) Name() string { return "ads" }

func (m adsModule) Enabled(cfg *config.Config) bool { return cfg.ScanADS }

func (m adsModule) Collect(ctx context.Context, fc *FileContext, data *FileRecord) error {
	streams, err := getAlternateDataStreams(fc.Path)
	if err == nil && len(streams) > 0 {
		data.AlternateDataStreams = streams
	}
	return nil
}

type mimeModule struct{}

func (m mimeModule) Name() string { return "mime" }

func (m mimeModule) Enabled(cfg *config.Config) bool { return cfg.ScanFiles }

func (m mimeModule) Collect(ctx context.Context, fc *FileContext, data *FileRecord) error {
	data.MimeType = fc.MimeType()
	return nil
}

type hashModule struct{}

func (m hashModule) Name() string { return "hashes" }

func (m hashModule) Enabled(cfg *config.Config) bool { return cfg.ScanFiles }

func (m hashModule) Collect(ctx context.Context, fc *FileContext, data *FileRecord) error {
	hashes := hasher.ComputeHashes(fc.Path, fc.Cfg.HashAlgorithms)
	data.Hashes = hashes
	return nil
}

type metadataModule struct{}

func (m metadataModule) Name() string { return "metadata" }

func (m metadataModule) Enabled(cfg *config.Config) bool { return cfg.ScanFiles }

func (m metadataModule) Collect(ctx context.Context, fc *FileContext, data *FileRecord) error {
	meta := metadata.ExtractMetadata(fc.Path, fc.MimeType(), fc.Cfg.MetadataMaxBytes)
	data.Metadata = meta
	return nil
}

type fuzzyModule struct {
	hashers []fuzzy.Hasher
}

func (m fuzzyModule) Name() string { return "fuzzy" }

func (m fuzzyModule) Enabled(cfg *config.Config) bool { return cfg.FuzzyHash && len(m.hashers) > 0 }

func (m fuzzyModule) Collect(ctx context.Context, fc *FileContext, data *FileRecord) error {
	if !m.Enabled(fc.Cfg) {
		return nil
	}
	size := fc.Info.Size()
	if size < fc.Cfg.FuzzyMinSize {
		return nil
	}
	if fc.Cfg.FuzzyMaxSize > 0 && size > fc.Cfg.FuzzyMaxSize {
		return nil
	}
	results := make(map[string]string)
	for _, hasher := range m.hashers {
		hash, err := hasher.HashFile(fc.Path)
		if err != nil {
			logger.Debugf("Fuzzy hash %s failed for %s: %v", hasher.Name(), fc.Path, err)
			continue
		}
		if hash != "" {
			results[hasher.Name()] = hash
		}
	}
	if len(results) > 0 {
		data.FuzzyHashes = results
	}
	return nil
}

type sensitiveModule struct {
	patternNames []string
}

func (m sensitiveModule) Name() string { return "sensitive" }

func (m sensitiveModule) Enabled(cfg *config.Config) bool { return cfg.ScanSensitive }

func (m sensitiveModule) Collect(ctx context.Context, fc *FileContext, data *FileRecord) error {
	if !fc.ShouldSearchContent() || len(fc.SensitivePatterns) == 0 {
		return nil
	}
	criticalPatterns := filterCriticalPatternNames(m.patternNames, fc.SensitivePatterns)
	var (
		matches map[string][]string
		counts  map[string]int
		err     error
	)
	if shouldUseDeterministicStreamSensitiveScan(
		fc.Cfg.ContentReadMode,
		fc.Cfg.SensitiveEngine,
		fc.Cfg.SensitiveLongtail,
		criticalPatterns,
		len(fc.Cfg.SearchTerms) > 0,
	) {
		maxSize := fc.Cfg.MaxFileSize
		if maxSize <= 0 || maxSize > maxContentScanBytes {
			maxSize = maxContentScanBytes
		}
		matches, counts, err = scanSensitiveDataDeterministicStream(
			fc.Path,
			fc.SensitivePatterns,
			criticalPatterns,
			fc.Cfg.SensitiveMaxPerType,
			fc.Cfg.SensitiveMaxTotal,
			fc.Cfg.StreamChunkSize,
			fc.Cfg.StreamOverlapBytes,
			maxSize,
		)
		if err != nil {
			return err
		}
	} else {
		content, err := fc.ContentBytes()
		if err != nil {
			return err
		}
		matches, counts = scanForSensitiveDataAdvanced(
			content,
			fc.SensitivePatterns,
			fc.Cfg.SensitiveMaxPerType,
			fc.Cfg.SensitiveMaxTotal,
			fc.Cfg.SensitiveEngine,
			fc.Cfg.SensitiveLongtail,
			fc.Cfg.SensitiveWindowBytes,
			m.patternNames,
		)
	}
	if len(matches) > 0 {
		matches = redactSensitiveData(matches, fc.Cfg.RedactSensitive)
		data.SensitiveData = matches
		data.SensitiveDataMatchCounts = counts
		if sensitiveMatchesMayBeTruncated(counts, fc.Cfg.SensitiveMaxPerType, fc.Cfg.SensitiveMaxTotal) {
			data.SensitiveDataTruncated = true
		}
	}
	return nil
}

type searchModule struct {
	counter prefilter.SearchCounter
}

func (m searchModule) Name() string { return "search" }

func (m searchModule) Enabled(cfg *config.Config) bool { return len(cfg.SearchTerms) > 0 }

func (m searchModule) Collect(ctx context.Context, fc *FileContext, data *FileRecord) error {
	if !fc.ShouldSearchContent() {
		return nil
	}
	counter := m.counter
	if counter == nil {
		counter = prefilter.BuildSearchCounter(fc.Cfg.SearchTerms)
	}
	var (
		hits map[string]int
		err  error
	)
	if shouldUseStreamSearchCounter(fc.Cfg.ContentReadMode, fc.content != nil, len(fc.Cfg.SearchTerms)) {
		maxSize := fc.Cfg.MaxFileSize
		if maxSize <= 0 || maxSize > maxContentScanBytes {
			maxSize = maxContentScanBytes
		}
		hits, err = countSearchTermsStream(fc.Path, fc.Cfg.SearchTerms, fc.Cfg.StreamChunkSize, maxSize)
		if err != nil {
			return err
		}
	} else {
		content, readErr := fc.ContentBytes()
		if readErr != nil {
			return readErr
		}
		hits = counter.CountBytes(content)
	}
	if len(hits) > 0 {
		data.SearchHits = hits
	}
	return nil
}

func buildFuzzyHashers(cfg *config.Config) []fuzzy.Hasher {
	if !cfg.FuzzyHash && len(cfg.FuzzyAlgorithms) == 0 {
		return nil
	}
	hashers := make([]fuzzy.Hasher, 0, len(cfg.FuzzyAlgorithms))
	for _, name := range cfg.FuzzyAlgorithms {
		hasher, ok := fuzzy.Lookup(name)
		if !ok {
			logger.Warnf("Unsupported fuzzy hash algorithm: %s", name)
			continue
		}
		hashers = append(hashers, hasher)
	}
	if len(hashers) == 0 && cfg.FuzzyHash {
		hasher, ok := fuzzy.Lookup("tlsh")
		if ok {
			hashers = append(hashers, hasher)
		}
	}
	return hashers
}

func getFileTimes(path string) (FileTimes, error) {
	return fileTimes(path)
}

func sensitiveMatchesMayBeTruncated(counts map[string]int, perTypeLimit, totalLimit int) bool {
	if perTypeLimit > 0 {
		for _, count := range counts {
			if count >= perTypeLimit {
				return true
			}
		}
	}
	if totalLimit > 0 {
		var total int
		for _, count := range counts {
			total += count
		}
		if total >= totalLimit {
			return true
		}
	}
	return false
}

var errNotSupported = errors.New("not supported")
