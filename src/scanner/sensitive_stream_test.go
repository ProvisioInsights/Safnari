package scanner

import (
	"os"
	"strings"
	"testing"
)

func TestScanSensitiveDataDeterministicStreamBoundaryParity(t *testing.T) {
	email := "test@example.com"
	aws := "AKIA" + "ABCDEFGHIJKLMNOP"
	jwt := "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.sig"
	ssn := "123-45-6789"

	content := strings.Repeat("x", 25) + " " + email + " " +
		strings.Repeat("y", 7) + " " + email + " " +
		strings.Repeat("z", 19) + " " + aws + " " +
		strings.Repeat("q", 13) + ssn + " " + jwt

	tmp, err := os.CreateTemp("", "sensitive-stream-*.txt")
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

	patternNames := []string{"email", "aws_access_key", "jwt_token", "ssn"}
	patterns := GetPatterns(patternNames, nil, nil)
	matches, counts, err := scanSensitiveDataDeterministicStream(
		tmp.Name(),
		patterns,
		patternNames,
		100,
		1000,
		64,
		48,
		1<<20,
	)
	if err != nil {
		t.Fatalf("stream scan: %v", err)
	}

	if counts["email"] != 2 {
		t.Fatalf("expected 2 email matches, got %d (%v)", counts["email"], matches["email"])
	}
	if counts["aws_access_key"] != 1 {
		t.Fatalf("expected 1 aws key match, got %d (%v)", counts["aws_access_key"], matches["aws_access_key"])
	}
	if counts["jwt_token"] != 1 {
		t.Fatalf("expected 1 jwt match, got %d (%v)", counts["jwt_token"], matches["jwt_token"])
	}
	if counts["ssn"] != 1 {
		t.Fatalf("expected 1 ssn match, got %d (%v)", counts["ssn"], matches["ssn"])
	}

	if !containsStringValue(matches["email"], email) {
		t.Fatalf("email missing from stream matches: %v", matches["email"])
	}
	if !containsStringValue(matches["aws_access_key"], aws) {
		t.Fatalf("aws key missing from stream matches: %v", matches["aws_access_key"])
	}
	if !containsStringValue(matches["jwt_token"], jwt) {
		t.Fatalf("jwt missing from stream matches: %v", matches["jwt_token"])
	}
	if !containsStringValue(matches["ssn"], ssn) {
		t.Fatalf("ssn missing from stream matches: %v", matches["ssn"])
	}
}

func containsStringValue(values []string, target string) bool {
	for _, v := range values {
		if v == target {
			return true
		}
	}
	return false
}
