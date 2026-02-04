package output

import "testing"

func BenchmarkMarshalFileData(b *testing.B) {
	data := map[string]interface{}{
		"path":      "/tmp/example.txt",
		"name":      "example.txt",
		"size":      int64(12345),
		"mod_time":  "2025-01-01T00:00:00Z",
		"mime_type": "text/plain",
		"hashes": map[string]string{
			"md5":    "0cc175b9c0f1b6a831c399e269772661",
			"sha256": "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
		},
		"metadata": map[string]string{
			"title":  "Example",
			"author": "UnitTest",
		},
		"sensitive_data": map[string][]string{
			"email": {"test@example.com"},
		},
		"search_hits": map[string]int{
			"password": 2,
		},
	}

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := jsonMarshalIndent(data, "    ", "  "); err != nil {
			b.Fatal(err)
		}
	}
}
