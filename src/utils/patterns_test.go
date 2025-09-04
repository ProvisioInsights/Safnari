package utils

import "testing"

func TestShouldInclude(t *testing.T) {
	if !ShouldInclude("file.txt", nil, nil) {
		t.Fatal("expected include by default")
	}
	if ShouldInclude("file.txt", []string{"*.jpg"}, nil) {
		t.Fatal("should not include unmatched include pattern")
	}
	if !ShouldInclude("photo.jpg", []string{"*.jpg"}, nil) {
		t.Fatal("should include matching include pattern")
	}
	if ShouldInclude("secret.txt", nil, []string{"secret.*"}) {
		t.Fatal("should exclude matching exclude pattern")
	}
	if !ShouldInclude("notes.txt", nil, []string{"secret.*"}) {
		t.Fatal("should include when exclude does not match")
	}
	if !ShouldInclude("path/to/file.go", []string{".*file\\.go$"}, nil) {
		t.Fatal("should match regex include pattern")
	}
}

func TestMatchesAnyPattern(t *testing.T) {
	if !matchesAnyPattern("file.txt", []string{"*.txt"}) {
		t.Fatal("expected wildcard match")
	}
	if matchesAnyPattern("file.txt", []string{"*.jpg"}) {
		t.Fatal("unexpected match")
	}
	if !matchesAnyPattern("dir/file.go", []string{"dir/.*\\.go"}) {
		t.Fatal("expected regex match")
	}
}
