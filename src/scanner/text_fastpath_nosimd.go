//go:build !simd || !amd64

package scanner

func simdBuildAvailable() bool {
	return false
}

func looksLikeTextSIMD(sample []byte) bool {
	return looksLikeTextGeneric(sample)
}
