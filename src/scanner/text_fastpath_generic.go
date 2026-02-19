package scanner

import "unicode/utf8"

func looksLikeTextGeneric(sample []byte) bool {
	if len(sample) == 0 {
		return false
	}
	if !utf8.Valid(sample) {
		return false
	}
	var control int
	for _, b := range sample {
		if b == 0 {
			return false
		}
		if b < 0x09 || (b > 0x0D && b < 0x20) {
			control++
		}
	}
	return control <= len(sample)/10
}
