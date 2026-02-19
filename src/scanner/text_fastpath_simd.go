//go:build simd && amd64

package scanner

import (
	"bytes"
	"unicode/utf8"
)

func simdBuildAvailable() bool {
	return true
}

// looksLikeTextSIMD provides the same semantics as the generic implementation,
// while using byte-search primitives that benefit from GOEXPERIMENT=simd on amd64.
func looksLikeTextSIMD(sample []byte) bool {
	if len(sample) == 0 {
		return false
	}
	if !utf8.Valid(sample) {
		return false
	}
	if bytes.IndexByte(sample, 0) >= 0 {
		return false
	}
	var control int
	for _, b := range sample {
		if b < 0x09 || (b > 0x0D && b < 0x20) {
			control++
		}
	}
	return control <= len(sample)/10
}
