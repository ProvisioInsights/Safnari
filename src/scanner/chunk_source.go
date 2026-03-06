package scanner

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"safnari/config"

	"github.com/h2non/filetype"
)

const (
	chunkSourceHeaderBytes = 4096
	chunkSourceLargeBuffer = 256 * 1024
)

var chunkSourceBufferPool = sync.Pool{
	New: func() interface{} {
		buf := make([]byte, chunkSourceLargeBuffer)
		return &buf
	},
}

// ChunkSource owns a single file descriptor and exposes reusable accessors for
// header sampling, text detection, and forward-only chunk iteration.
type ChunkSource struct {
	path string
	info os.FileInfo
	cfg  *config.Config

	file *os.File

	header    []byte
	mimeType  string
	likelyTxt bool
}

func openChunkSource(path string, info os.FileInfo, cfg *config.Config) (*ChunkSource, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	s := &ChunkSource{
		path: path,
		info: info,
		cfg:  cfg,
		file: file,
	}
	if err := s.initHeader(); err != nil {
		_ = file.Close()
		return nil, err
	}
	return s, nil
}

func (s *ChunkSource) initHeader() error {
	if s == nil || s.file == nil {
		return fmt.Errorf("chunk source is not open")
	}
	size := chunkSourceHeaderBytes
	if s.info != nil && s.info.Size() > 0 && s.info.Size() < int64(size) {
		size = int(s.info.Size())
	}
	if size < 0 {
		size = 0
	}
	s.header = make([]byte, size)
	if size == 0 {
		s.mimeType = "unknown"
		return nil
	}
	n, err := s.file.ReadAt(s.header, 0)
	if err != nil && err != io.EOF {
		return err
	}
	s.header = s.header[:n]
	kind, matchErr := filetype.Match(s.header)
	if matchErr != nil || kind == filetype.Unknown || kind.MIME.Value == "" {
		s.mimeType = "unknown"
	} else {
		s.mimeType = kind.MIME.Value
	}
	s.likelyTxt = looksLikeText(s.header)
	return nil
}

func (s *ChunkSource) Close() error {
	if s == nil || s.file == nil {
		return nil
	}
	err := s.file.Close()
	s.file = nil
	return err
}

func (s *ChunkSource) File() *os.File {
	if s == nil {
		return nil
	}
	return s.file
}

func (s *ChunkSource) MimeType() string {
	if s == nil || s.mimeType == "" {
		return "unknown"
	}
	return s.mimeType
}

func (s *ChunkSource) Header() []byte {
	if s == nil {
		return nil
	}
	return s.header
}

func (s *ChunkSource) ShouldSearchContent() bool {
	if s == nil {
		return false
	}
	if hasLikelyTextExtension(s.path) {
		return true
	}
	mimeType := s.MimeType()
	if strings.HasPrefix(mimeType, "text/") ||
		strings.Contains(mimeType, "json") ||
		strings.Contains(mimeType, "xml") ||
		strings.Contains(mimeType, "html") ||
		strings.Contains(mimeType, "javascript") {
		return true
	}
	if mimeType == "unknown" || mimeType == "application/octet-stream" {
		return s.likelyTxt
	}
	return false
}

func (s *ChunkSource) SectionReader(limit int64) *io.SectionReader {
	if s == nil || s.file == nil {
		return io.NewSectionReader(strings.NewReader(""), 0, 0)
	}
	size := int64(0)
	if s.info != nil {
		size = s.info.Size()
	}
	if limit > 0 && (size == 0 || size > limit) {
		size = limit
	}
	if size < 0 {
		size = 0
	}
	return io.NewSectionReader(s.file, 0, size)
}

func (s *ChunkSource) ReadAll(limit int64) ([]byte, error) {
	reader := s.SectionReader(limit)
	if reader == nil {
		return nil, fmt.Errorf("chunk source is not open")
	}
	return io.ReadAll(reader)
}

func (s *ChunkSource) ReadRange(start, length int64) ([]byte, error) {
	if s == nil || s.file == nil {
		return nil, fmt.Errorf("chunk source is not open")
	}
	if start < 0 {
		start = 0
	}
	if length < 0 {
		length = 0
	}
	size := int64(0)
	if s.info != nil {
		size = s.info.Size()
	}
	if start > size {
		start = size
	}
	if start+length > size {
		length = size - start
	}
	if length < 0 {
		length = 0
	}
	return io.ReadAll(io.NewSectionReader(s.file, start, length))
}

func (s *ChunkSource) Scan(limit int64, fn func(chunk []byte, offset int64) error) error {
	if s == nil || s.file == nil {
		return fmt.Errorf("chunk source is not open")
	}
	if fn == nil {
		return nil
	}
	chunkSize := chunkSourceLargeBuffer
	if s.cfg != nil && s.cfg.StreamChunkSize > 0 {
		chunkSize = s.cfg.StreamChunkSize
	}
	bufPtr := chunkSourceBufferPool.Get().(*[]byte)
	defer chunkSourceBufferPool.Put(bufPtr)

	buf := *bufPtr
	if len(buf) < chunkSize {
		buf = make([]byte, chunkSize)
	} else {
		buf = buf[:chunkSize]
	}

	reader := s.SectionReader(limit)
	var offset int64
	for {
		n, err := reader.Read(buf)
		if n > 0 {
			if consumeErr := fn(buf[:n], offset); consumeErr != nil {
				return consumeErr
			}
			offset += int64(n)
		}
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
	}
}

func normalizeChunkCacheDir(dir string) string {
	dir = strings.TrimSpace(dir)
	if dir == "" {
		return ""
	}
	cleaned := filepath.Clean(dir)
	if cleaned == "." {
		return ""
	}
	return cleaned
}
