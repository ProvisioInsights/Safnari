package scanner

import (
	"context"
	"errors"
	"fmt"
	"os"
	"regexp"
	"sort"
	"time"

	"safnari/config"
	"safnari/fuzzy"
	"safnari/logger"
	"safnari/metadata"
	"safnari/scanner/prefilter"
)

const defaultContentScanMaxBytes int64 = 10 * 1024 * 1024

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
	deltaCache        *DeltaChunkCache

	source *ChunkSource

	mimeLoaded  bool
	mimeType    string
	content     []byte
	contentText string
	contentErr  error
	textLoaded  bool

	analysisLoaded bool
	analysisErr    error
	analysis       *contentAnalysisResults

	contentScanBytes     int64
	contentScanTruncated bool
	warnings             []string
	warningSet           map[string]struct{}
	sizeLimitNoted       bool
}

func (fc *FileContext) MimeType() string {
	if fc.mimeLoaded {
		return fc.mimeType
	}
	source, err := fc.Source()
	if err != nil {
		fc.mimeType = "unknown"
		fc.mimeLoaded = true
		return fc.mimeType
	}
	fc.mimeType = source.MimeType()
	fc.mimeLoaded = true
	return fc.mimeType
}

func (fc *FileContext) ContentBytes() ([]byte, error) {
	if fc.content != nil || fc.contentErr != nil {
		return fc.content, fc.contentErr
	}
	maxSize := fc.contentScanLimit()
	source, err := fc.Source()
	if err != nil {
		fc.contentErr = err
		return nil, err
	}
	content, err := source.ReadAll(maxSize)
	fc.content = content
	fc.contentErr = err
	if err == nil {
		fc.markContentScan(maxSize)
	}
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
	source, err := fc.Source()
	if err != nil {
		if hasLikelyTextExtension(fc.Path) {
			return true
		}
		return false
	}
	return source.ShouldSearchContent()
}

func (fc *FileContext) FullFileProcessingAllowed() bool {
	if fc == nil || fc.Cfg == nil || fc.Info == nil {
		return true
	}
	if fc.Cfg.MaxFileSize <= 0 {
		return true
	}
	return fc.Info.Size() <= fc.Cfg.MaxFileSize
}

func (fc *FileContext) NoteFullFileProcessingSkipped() {
	if fc == nil || fc.sizeLimitNoted || fc.Cfg == nil || fc.Info == nil || fc.Cfg.MaxFileSize <= 0 {
		return
	}
	if fc.Info.Size() <= fc.Cfg.MaxFileSize {
		return
	}
	fc.sizeLimitNoted = true
	fc.addWarning(fmt.Sprintf("full-file operations skipped for files larger than %d bytes", fc.Cfg.MaxFileSize))
}

func (fc *FileContext) contentScanLimit() int64 {
	if fc == nil || fc.Cfg == nil {
		return defaultContentScanMaxBytes
	}
	if fc.Cfg.ContentScanMaxBytes == 0 {
		return 0
	}
	if fc.Cfg.ContentScanMaxBytes < 0 {
		return 0
	}
	return fc.Cfg.ContentScanMaxBytes
}

func (fc *FileContext) markContentScan(limit int64) {
	if fc == nil || fc.Info == nil {
		return
	}
	size := fc.Info.Size()
	if size < 0 {
		return
	}
	scanned := size
	truncated := false
	if limit > 0 && size > limit {
		scanned = limit
		truncated = true
	}
	if scanned > fc.contentScanBytes {
		fc.contentScanBytes = scanned
	}
	if truncated {
		fc.contentScanTruncated = true
		fc.addWarning(fmt.Sprintf("content scan truncated at %d bytes", limit))
	}
}

func (fc *FileContext) addWarning(msg string) {
	if fc == nil || msg == "" {
		return
	}
	if fc.warningSet == nil {
		fc.warningSet = make(map[string]struct{}, 4)
	}
	if _, ok := fc.warningSet[msg]; ok {
		return
	}
	fc.warningSet[msg] = struct{}{}
	fc.warnings = append(fc.warnings, msg)
}

func (fc *FileContext) Source() (*ChunkSource, error) {
	if fc == nil {
		return nil, fmt.Errorf("file context is nil")
	}
	if fc.source != nil {
		return fc.source, nil
	}
	source, err := openChunkSource(fc.Path, fc.Info, fc.Cfg)
	if err != nil {
		return nil, err
	}
	fc.source = source
	return source, nil
}

func (fc *FileContext) Close() error {
	if fc == nil || fc.source == nil {
		return nil
	}
	err := fc.source.Close()
	fc.source = nil
	return err
}

func (fc *FileContext) EnsureContentAnalysis() (*contentAnalysisResults, error) {
	if fc == nil {
		return &contentAnalysisResults{}, nil
	}
	if fc.analysisLoaded || fc.analysisErr != nil {
		if fc.analysis == nil {
			fc.analysis = &contentAnalysisResults{}
		}
		return fc.analysis, fc.analysisErr
	}
	fc.analysisLoaded = true
	fc.analysis, fc.analysisErr = runContentPipeline(fc)
	if fc.analysis == nil {
		fc.analysis = &contentAnalysisResults{}
	}
	return fc.analysis, fc.analysisErr
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
	if !fc.FullFileProcessingAllowed() {
		fc.NoteFullFileProcessingSkipped()
		return nil
	}
	results, err := fc.EnsureContentAnalysis()
	if err != nil {
		return err
	}
	data.Hashes = results.hashes
	return nil
}

type metadataModule struct{}

func (m metadataModule) Name() string { return "metadata" }

func (m metadataModule) Enabled(cfg *config.Config) bool { return cfg.ScanFiles }

func (m metadataModule) Collect(ctx context.Context, fc *FileContext, data *FileRecord) error {
	if !fc.FullFileProcessingAllowed() {
		fc.NoteFullFileProcessingSkipped()
		return nil
	}
	source, err := fc.Source()
	if err != nil {
		return err
	}
	file := source.File()
	size := int64(0)
	if fc.Info != nil {
		size = fc.Info.Size()
	}
	meta := metadata.ExtractMetadataFromFile(file, size, fc.MimeType(), fc.Path, fc.Cfg.MetadataMaxBytes)
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
	if !fc.FullFileProcessingAllowed() {
		fc.NoteFullFileProcessingSkipped()
		return nil
	}
	size := fc.Info.Size()
	if size < fc.Cfg.FuzzyMinSize {
		return nil
	}
	if fc.Cfg.FuzzyMaxSize > 0 && size > fc.Cfg.FuzzyMaxSize {
		return nil
	}
	results, err := fc.EnsureContentAnalysis()
	if err != nil {
		return err
	}
	if len(results.fuzzyHashes) > 0 {
		data.FuzzyHashes = results.fuzzyHashes
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
	results, err := fc.EnsureContentAnalysis()
	if err != nil {
		return err
	}
	matches := results.sensitiveMatches
	counts := results.sensitiveMatchCount
	if len(matches) > 0 {
		matches = redactSensitiveData(matches, fc.Cfg.RedactSensitive)
		data.SensitiveData = matches
		data.SensitiveDataMatchCounts = counts
		if sensitiveMatchMode(fc.Cfg) == "first" {
			fc.addWarning("sensitive-match-mode=first stores only the first retained match for each matching type")
		}
		if sensitiveMatchesMayBeTruncated(counts, effectiveSensitivePerTypeLimit(fc.Cfg), fc.Cfg.SensitiveMaxTotal) || sensitiveMatchMode(fc.Cfg) == "first" {
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
	results, err := fc.EnsureContentAnalysis()
	if err != nil {
		return err
	}
	if len(results.searchHits) > 0 {
		data.SearchHits = results.searchHits
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

func (fc *FileContext) applyRecordState(data *FileRecord) {
	if fc == nil || data == nil {
		return
	}
	if fc.contentScanBytes > 0 {
		data.ContentScanBytes = fc.contentScanBytes
	}
	if fc.contentScanTruncated {
		data.ContentScanTruncated = true
	}
	if len(fc.warnings) > 0 {
		data.CollectionWarnings = append(data.CollectionWarnings, fc.warnings...)
	}
}

var errNotSupported = errors.New("not supported")
