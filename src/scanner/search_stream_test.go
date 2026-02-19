package scanner

import (
	"os"
	"testing"
)

func TestCountSearchTermsStreamParity(t *testing.T) {
	content := "alpha beta alpha gamma\n" +
		"aaaa\n" +
		"term-at-boundary-start END\n" +
		"END term-at-boundary-end"
	terms := []string{"alpha", "aaaa", "END", "missing", "", "alpha"}

	tmp, err := os.CreateTemp("", "search-stream-*.txt")
	if err != nil {
		t.Fatalf("temp: %v", err)
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.WriteString(content); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := tmp.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	streamHits, err := countSearchTermsStream(tmp.Name(), terms, 16, 1<<20)
	if err != nil {
		t.Fatalf("stream count: %v", err)
	}
	want := scanForSearchTerms(content, terms)
	if len(streamHits) != len(want) {
		t.Fatalf("hit map length mismatch: got=%v want=%v", streamHits, want)
	}
	for term, wantCount := range want {
		if streamHits[term] != wantCount {
			t.Fatalf("count mismatch for %q: got=%d want=%d", term, streamHits[term], wantCount)
		}
	}
}

func TestCountSearchTermsStreamHonorsMaxSize(t *testing.T) {
	tmp, err := os.CreateTemp("", "search-stream-max-*.txt")
	if err != nil {
		t.Fatalf("temp: %v", err)
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.WriteString("alpha alpha alpha"); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := tmp.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	hits, err := countSearchTermsStream(tmp.Name(), []string{"alpha"}, 8, 4)
	if err != nil {
		t.Fatalf("stream count: %v", err)
	}
	if hits != nil {
		t.Fatalf("expected nil hits when max size is exceeded, got %v", hits)
	}
}

func TestShouldUseStreamSearchCounter(t *testing.T) {
	if shouldUseStreamSearchCounter("stream", false, 2) != true {
		t.Fatal("expected stream counter to be enabled")
	}
	if shouldUseStreamSearchCounter("auto", false, 2) {
		t.Fatal("expected stream counter disabled for auto mode")
	}
	if shouldUseStreamSearchCounter("stream", true, 2) {
		t.Fatal("expected stream counter disabled when content cache exists")
	}
	if shouldUseStreamSearchCounter("stream", false, 0) {
		t.Fatal("expected stream counter disabled with zero terms")
	}
}
