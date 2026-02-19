package scanner

import (
	"bytes"
	"testing"
)

func BenchmarkLooksLikeTextFast(b *testing.B) {
	sample := bytes.Repeat([]byte("The quick brown fox jumps over the lazy dog.\n"), 256)
	b.Run("generic", func(b *testing.B) {
		setSIMDFastpathEnabled(false)
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if !looksLikeTextFast(sample) {
				b.Fatal("expected text sample to be classified as text")
			}
		}
	})

	b.Run("simd", func(b *testing.B) {
		setSIMDFastpathEnabled(true)
		defer setSIMDFastpathEnabled(false)
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if !looksLikeTextFast(sample) {
				b.Fatal("expected text sample to be classified as text")
			}
		}
	})
}

func BenchmarkLooksLikeTextFastBinary(b *testing.B) {
	sample := bytes.Repeat([]byte{0x00, 0x01, 0x02, 0x03, 0x04}, 512)
	b.Run("generic", func(b *testing.B) {
		setSIMDFastpathEnabled(false)
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if looksLikeTextFast(sample) {
				b.Fatal("expected binary sample to be classified as non-text")
			}
		}
	})

	b.Run("simd", func(b *testing.B) {
		setSIMDFastpathEnabled(true)
		defer setSIMDFastpathEnabled(false)
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if looksLikeTextFast(sample) {
				b.Fatal("expected binary sample to be classified as non-text")
			}
		}
	})
}
