package prefilter

import (
	"strings"
	"testing"
)

func BenchmarkTokenContains(b *testing.B) {
	content := strings.Repeat("prefix token suffix ", 1024)
	b.Run("generic", func(b *testing.B) {
		SetSIMDFastpath(false)
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if !tokenContains(content, "token") {
				b.Fatal("expected token to be found")
			}
		}
	})
	b.Run("simd", func(b *testing.B) {
		SetSIMDFastpath(true)
		defer SetSIMDFastpath(false)
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if !tokenContains(content, "token") {
				b.Fatal("expected token to be found")
			}
		}
	})
}
