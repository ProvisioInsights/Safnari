package sensitive

import (
	"reflect"
	"testing"
)

func TestScanDeterministicAllParityWithPerPatternScans(t *testing.T) {
	content := []byte(
		"test@example.com " +
			"4111-1111-1111-1111 " +
			"123-45-6789 " +
			"api_key=abcd1234 " +
			"AKIA" + "ABCDEFGHIJKLMNOP " +
			"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.sig",
	)
	patterns := []string{"email", "credit_card", "ssn", "api_key", "aws_access_key", "jwt_token"}

	allMatches, allCounts := ScanDeterministicAll(content, patterns, 100, 1000)
	for _, pattern := range patterns {
		want := ScanDeterministic(content, pattern, 100)
		got := allMatches[pattern]
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("deterministic all mismatch for %s: got=%v want=%v", pattern, got, want)
		}
		if allCounts[pattern] != len(want) {
			t.Fatalf("deterministic count mismatch for %s: got=%d want=%d", pattern, allCounts[pattern], len(want))
		}
	}
}

func TestScanDeterministicMatchesRespectsLimits(t *testing.T) {
	content := []byte(
		"a@test.com b@test.com c@test.com " +
			"AKIA" + "ABCDEFGHIJKLMNOP " + "AKIA" + "ABCDEFGHIJKLMNOQ",
	)
	patterns := []string{"email", "aws_access_key"}

	matches := ScanDeterministicMatches(content, patterns, 1, 1)
	if len(matches) != 1 {
		t.Fatalf("expected total limit to cap matches at 1, got %d", len(matches))
	}

	perType := ScanDeterministicMatches(content, patterns, 1, 0)
	var emailCount, awsCount int
	for _, m := range perType {
		switch m.Pattern {
		case "email":
			emailCount++
		case "aws_access_key":
			awsCount++
		}
	}
	if emailCount > 1 || awsCount > 1 {
		t.Fatalf("expected per-type limit of 1, got email=%d aws=%d", emailCount, awsCount)
	}
}
