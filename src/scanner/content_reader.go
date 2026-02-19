package scanner

import (
	"io"
	"os"
	"strings"

	"golang.org/x/exp/mmap"
)

var openMmapReader = mmap.Open

func readFileContentWithMode(
	path string,
	maxSize int64,
	mode string,
	mmapMinSize int64,
	streamChunkSize int,
	streamOverlapBytes int,
) ([]byte, error) {
	maxSize = clampContentMaxSize(maxSize)
	if mmapMinSize <= 0 {
		mmapMinSize = 128 * 1024
	}
	if streamChunkSize <= 0 {
		streamChunkSize = 256 * 1024
	}
	if streamOverlapBytes < 0 {
		streamOverlapBytes = 0
	}
	if streamOverlapBytes >= streamChunkSize {
		streamChunkSize = streamOverlapBytes * 2
	}
	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode == "" {
		mode = "auto"
	}

	switch mode {
	case "stream":
		return readFileContentStream(path, maxSize, streamChunkSize)
	case "mmap":
		return readFileContentMmap(path, maxSize)
	case "auto":
		info, err := os.Stat(path)
		if err != nil {
			return nil, err
		}
		if maxSize > 0 && info.Size() > maxSize {
			return nil, nil
		}
		if info.Size() >= mmapMinSize {
			content, err := readFileContentMmap(path, maxSize)
			if err == nil {
				return content, nil
			}
		}
		return readFileContentStream(path, maxSize, streamChunkSize)
	default:
		return readFileContentStream(path, maxSize, streamChunkSize)
	}
}

func readFileContentMmap(path string, maxSize int64) ([]byte, error) {
	maxSize = clampContentMaxSize(maxSize)
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if maxSize > 0 && info.Size() > maxSize {
		return nil, nil
	}

	r, err := openMmapReader(path)
	if err != nil {
		return nil, err
	}
	defer r.Close()

	readSize := info.Size()
	if maxSize > 0 && readSize > maxSize {
		readSize = maxSize
	}
	if readSize <= 0 {
		return []byte{}, nil
	}

	buf := make([]byte, readSize)
	_, err = r.ReadAt(buf, 0)
	if err != nil {
		return nil, err
	}
	return buf, nil
}

func readFileContentStream(path string, maxSize int64, chunkSize int) ([]byte, error) {
	maxSize = clampContentMaxSize(maxSize)
	if chunkSize <= 0 {
		chunkSize = 256 * 1024
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	if maxSize > 0 {
		stat, err := file.Stat()
		if err == nil && stat.Size() > maxSize {
			return nil, nil
		}
		if err == nil && stat.Size() > 0 {
			capHint := stat.Size()
			if maxSize > 0 && capHint > maxSize {
				capHint = maxSize
			}
			content := make([]byte, 0, capHint)
			return readContentChunks(file, content, chunkSize, maxSize)
		}
	}
	return readContentChunks(file, nil, chunkSize, maxSize)
}

func readFileContentStandard(path string, maxSize int64) ([]byte, error) {
	return readFileContentStream(path, maxSize, 256*1024)
}

func readContentChunks(file *os.File, content []byte, chunkSize int, maxSize int64) ([]byte, error) {
	buffer := make([]byte, chunkSize)
	var total int64
	for {
		n, err := file.Read(buffer)
		if n > 0 {
			chunk := buffer[:n]
			if maxSize > 0 && total+int64(n) > maxSize {
				allowed := int(maxSize - total)
				if allowed < 0 {
					allowed = 0
				}
				chunk = chunk[:allowed]
			}
			content = append(content, chunk...)
			total += int64(len(chunk))
			if maxSize > 0 && total >= maxSize {
				break
			}
		}
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}
	}
	return content, nil
}

func clampContentMaxSize(maxSize int64) int64 {
	if maxSize <= 0 || maxSize > maxContentScanBytes {
		return maxContentScanBytes
	}
	return maxSize
}
