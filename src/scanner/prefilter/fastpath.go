package prefilter

import "sync/atomic"

var simdFastpathEnabled atomic.Bool

func SetSIMDFastpath(enabled bool) {
	simdFastpathEnabled.Store(enabled)
}

func tokenContains(content, token string) bool {
	if simdFastpathEnabled.Load() && simdTokenBuildAvailable() {
		return tokenContainsSIMD(content, token)
	}
	return tokenContainsGeneric(content, token)
}
