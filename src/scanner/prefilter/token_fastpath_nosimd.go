//go:build !simd || !amd64

package prefilter

func simdTokenBuildAvailable() bool {
	return false
}

func tokenContainsSIMD(content, token string) bool {
	return tokenContainsGeneric(content, token)
}
