package utils

import "testing"

func TestShouldInclude(t *testing.T) {
	matcher := NewPatternMatcher(nil, nil)
	if !matcher.ShouldInclude("file.txt") {
		t.Fatal("expected include by default")
	}
	matcher = NewPatternMatcher([]string{"*.jpg"}, nil)
	if matcher.ShouldInclude("file.txt") {
		t.Fatal("should not include unmatched include pattern")
	}
	if !matcher.ShouldInclude("photo.jpg") {
		t.Fatal("should include matching include pattern")
	}
	matcher = NewPatternMatcher(nil, []string{"secret.*"})
	if matcher.ShouldInclude("secret.txt") {
		t.Fatal("should exclude matching exclude pattern")
	}
	if !matcher.ShouldInclude("notes.txt") {
		t.Fatal("should include when exclude does not match")
	}
	matcher = NewPatternMatcher([]string{".*file\\.go$"}, nil)
	if !matcher.ShouldInclude("path/to/file.go") {
		t.Fatal("should match regex include pattern")
	}
}
