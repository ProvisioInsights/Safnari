package prefilter

import (
	"bytes"
	"reflect"
	"sort"
	"strings"
	"testing"
)

func TestSearchCounterParityWithByteCount(t *testing.T) {
	terms := []string{"alpha", "Beta", "alpha", ""}
	content := "alpha Beta alpha alphabet beta"

	counter := BuildSearchCounter(terms)
	counts := counter.Count(content)
	expected := map[string]int{
		"alpha": bytes.Count([]byte(content), []byte("alpha")),
		"Beta":  bytes.Count([]byte(content), []byte("Beta")),
	}

	if !reflect.DeepEqual(expected, counts) {
		t.Fatalf("search counter mismatch: expected=%v got=%v", expected, counts)
	}
}

func TestSearchCounterAutoUsesAhoForLargeInputs(t *testing.T) {
	terms := []string{"alpha", "beta", "gamma", "delta", "epsilon", "zeta", "eta", "theta", "iota"}
	content := strings.Repeat("alpha beta gamma delta epsilon zeta eta theta iota ", 256)

	counter := BuildSearchCounter(terms)
	counts := counter.Count(content)
	for _, term := range terms {
		expected := bytes.Count([]byte(content), []byte(term))
		if counts[term] != expected {
			t.Fatalf("term %q mismatch: expected=%d got=%d", term, expected, counts[term])
		}
	}
}

func TestSensitiveGateSafeMode(t *testing.T) {
	patterns := []string{"email", "api_key", "custom"}
	sort.Strings(patterns)

	gate := BuildSensitiveGate("safe", "contact us at test@example.com", patterns)
	if !gate.Allow("email") {
		t.Fatal("expected safe gate to allow email pattern")
	}
	if gate.Allow("api_key") {
		t.Fatal("did not expect api_key token to pass safe gate")
	}
	if !gate.Allow("custom") {
		t.Fatal("expected unknown pattern names to stay allowed in safe mode")
	}
}

func TestSensitiveGateAggressiveMode(t *testing.T) {
	patterns := []string{"email", "credit_card", "aws_access_key"}
	sort.Strings(patterns)

	awsLike := "AKIA" + "ABCDEFGHIJKLMNOP"
	gate := BuildSensitiveGate("aggressive", "token "+awsLike+" and foo@example.com", patterns)
	if !gate.Allow("email") {
		t.Fatal("expected aggressive gate to allow email")
	}
	if !gate.Allow("aws_access_key") {
		t.Fatal("expected aggressive gate to allow aws_access_key")
	}
	if gate.Allow("credit_card") {
		t.Fatal("did not expect credit_card token to pass aggressive gate")
	}
}

func TestSensitiveGateSafeModeCaseInsensitive(t *testing.T) {
	patterns := []string{"aws_access_key", "jwt_token", "api_key"}
	sort.Strings(patterns)
	content := "AKIA" + "ABCDEFGHIJKLMNOP token eyJabc.def.ghi and API_KEY=abc123"
	gate := BuildSensitiveGate("safe", content, patterns)
	for _, pattern := range patterns {
		if !gate.Allow(pattern) {
			t.Fatalf("expected case-insensitive safe gate match for %s", pattern)
		}
	}
}

func TestSensitiveGateSafeModeShapeGateAllowsRepresentativeMatches(t *testing.T) {
	patterns := []string{
		"credit_card",
		"ssn",
		"ip_address",
		"phone_number",
		"street_address",
		"iban",
		"uk_nin",
		"eu_vat",
		"india_aadhaar",
		"china_id",
	}
	sort.Strings(patterns)
	content := strings.Join([]string{
		"4111-1111-1111-1111",
		"123-45-6789",
		"10.20.30.40",
		"(212) 555-1212",
		"123 Main Street",
		"GB29NWBK60161331926819",
		"QQ123456C",
		"DE12345678",
		"1234 5678 9012",
		"11010519491231002X",
	}, " ")

	gate := BuildSensitiveGate("safe", content, patterns)
	for _, pattern := range patterns {
		if !gate.Allow(pattern) {
			t.Fatalf("expected safe gate to allow representative match for %s", pattern)
		}
	}
}

func TestSensitiveGateSafeModeShapeGateBlocksClearlyImpossibleContent(t *testing.T) {
	patterns := []string{"credit_card", "phone_number", "india_aadhaar", "china_id", "uk_nin"}
	sort.Strings(patterns)
	content := "plain words only with no digits at all"

	gate := BuildSensitiveGate("safe", content, patterns)
	for _, pattern := range patterns {
		if gate.Allow(pattern) {
			t.Fatalf("expected safe gate to block %s for no-digit content", pattern)
		}
	}
}

func TestTokenContainsStableAcrossSIMDToggle(t *testing.T) {
	content := "prefix token suffix"
	SetSIMDFastpath(false)
	base := tokenContains(content, "token")

	SetSIMDFastpath(true)
	optimized := tokenContains(content, "token")
	SetSIMDFastpath(false)

	if base != optimized {
		t.Fatalf("expected stable tokenContains result across SIMD toggle, base=%t optimized=%t", base, optimized)
	}
}
