//go:build simd && amd64

package prefilter

import "strings"

func simdTokenBuildAvailable() bool {
	return true
}

func tokenContainsSIMD(content, token string) bool {
	// strings.Contains avoids string->[]byte allocations and still benefits from
	// Go runtime/stdlib search optimizations under GOEXPERIMENT=simd.
	return strings.Contains(content, token)
}
