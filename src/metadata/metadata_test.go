package metadata

import "testing"

func TestExtractMetadata(t *testing.T) {
	cases := []string{
		"image/jpeg",
		"application/pdf",
		"application/vnd.openxmlformats-officedocument.wordprocessingml.document",
		"unknown",
	}
	for _, mime := range cases {
		meta := ExtractMetadata("", mime, 1024)
		if meta == nil {
			t.Fatalf("metadata map nil for %s", mime)
		}
	}
}
