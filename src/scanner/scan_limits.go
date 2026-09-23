package scanner

func clampContentMaxSize(maxSize int64) int64 {
	if maxSize < 0 {
		return defaultContentScanMaxBytes
	}
	return maxSize
}
