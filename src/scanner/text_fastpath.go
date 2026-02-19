package scanner

import "sync/atomic"

var simdFastpathEnabled atomic.Bool

func setSIMDFastpathEnabled(enabled bool) {
	simdFastpathEnabled.Store(enabled)
}

func looksLikeTextFast(sample []byte) bool {
	if simdFastpathEnabled.Load() && simdBuildAvailable() {
		return looksLikeTextSIMD(sample)
	}
	return looksLikeTextGeneric(sample)
}
