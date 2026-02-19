package prefilter

import (
	"bytes"
	"strings"

	"github.com/cloudflare/ahocorasick"
)

type SearchCounter interface {
	Count(content string) map[string]int
	CountBytes(content []byte) map[string]int
}

const (
	autoAhoMinTerms        = 8
	autoAhoMinContentBytes = 4 * 1024
)

type naiveSearchCounter struct {
	terms     []string
	termsByte [][]byte
}

func (c naiveSearchCounter) Count(content string) map[string]int {
	return c.CountBytes([]byte(content))
}

func (c naiveSearchCounter) CountBytes(content []byte) map[string]int {
	var hits map[string]int
	for i, term := range c.terms {
		if term == "" {
			continue
		}
		count := bytes.Count(content, c.termsByte[i])
		if count > 0 {
			if hits == nil {
				hits = make(map[string]int, 4)
			}
			hits[term] = count
		}
	}
	return hits
}

type ahoSearchCounter struct {
	terms     []string
	termsByte [][]byte
	matcher   *ahocorasick.Matcher
}

func (c ahoSearchCounter) Count(content string) map[string]int {
	return c.CountBytes([]byte(content))
}

func (c ahoSearchCounter) CountBytes(content []byte) map[string]int {
	matches := c.matcher.MatchThreadSafe(content)
	if len(matches) == 0 {
		return nil
	}

	candidates := make([]bool, len(c.terms))
	for _, idx := range matches {
		if idx < 0 || idx >= len(c.terms) {
			continue
		}
		candidates[idx] = true
	}

	var hits map[string]int
	for i := range candidates {
		if !candidates[i] {
			continue
		}
		count := bytes.Count(content, c.termsByte[i])
		if count > 0 {
			if hits == nil {
				hits = make(map[string]int, len(candidates))
			}
			hits[c.terms[i]] = count
		}
	}
	return hits
}

type autoSearchCounter struct {
	naive naiveSearchCounter
	aho   ahoSearchCounter
}

func (c autoSearchCounter) Count(content string) map[string]int {
	return c.CountBytes([]byte(content))
}

func (c autoSearchCounter) CountBytes(content []byte) map[string]int {
	if len(c.naive.terms) < autoAhoMinTerms || len(content) < autoAhoMinContentBytes {
		return c.naive.CountBytes(content)
	}
	return c.aho.CountBytes(content)
}

func BuildSearchCounter(terms []string) SearchCounter {
	normalized := normalizeTerms(terms)
	termBytes := make([][]byte, len(normalized))
	for i := range normalized {
		termBytes[i] = []byte(normalized[i])
	}
	naive := naiveSearchCounter{terms: normalized, termsByte: termBytes}
	if len(normalized) == 0 {
		return naive
	}

	aho := ahoSearchCounter{terms: normalized, termsByte: termBytes, matcher: ahocorasick.NewStringMatcher(normalized)}
	return autoSearchCounter{naive: naive, aho: aho}
}

type SensitiveGate struct {
	allowAll bool
	allowed  map[string]bool
}

func (g SensitiveGate) Allow(pattern string) bool {
	if g.allowAll {
		return true
	}
	return g.allowed[pattern]
}

func BuildSensitiveGate(mode, content string, patternNames []string) SensitiveGate {
	return BuildSensitiveGateBytes(mode, []byte(content), patternNames)
}

func BuildSensitiveGateBytes(mode string, content []byte, patternNames []string) SensitiveGate {
	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode == "" || mode == "off" || len(patternNames) == 0 {
		return SensitiveGate{allowAll: true}
	}

	switch mode {
	case "safe":
		stats := scanContentStats(content)
		allowed := make(map[string]bool, len(patternNames))
		for _, name := range patternNames {
			if !passesSafeShapeGate(name, stats) {
				allowed[name] = false
				continue
			}
			tokens, ok := safePatternTokenBytes[name]
			if !ok {
				allowed[name] = true
				continue
			}
			allowed[name] = containsAnyTokenBytes(content, tokens, true)
		}
		return SensitiveGate{allowed: allowed}
	case "aggressive":
		lowerContent := strings.ToLower(string(content))
		return aggressiveGate(lowerContent, patternNames)
	default:
		return SensitiveGate{allowAll: true}
	}
}

var safePatternTokens = map[string][]string{
	"email":          {"@"},
	"ssn":            {"-"},
	"ip_address":     {"."},
	"api_key":        {"api_key", "api-secret", "access-token"},
	"aws_access_key": {"akia"},
	"jwt_token":      {"eyj"},
	"street_address": {" street", " avenue", " road", " lane", " drive"},
}

var aggressivePatternTokens = map[string][]string{
	"email":          {"@"},
	"credit_card":    {"-", " "},
	"ssn":            {"-"},
	"ip_address":     {"."},
	"api_key":        {"api_key", "api-secret", "access-token", "key", "token"},
	"phone_number":   {"(", ")", "-", "."},
	"aws_access_key": {"akia"},
	"jwt_token":      {"eyj", "."},
	"street_address": {" street", " avenue", " road", " lane", " drive"},
	"iban":           {"gb", "de", "fr", "es", "it", "nl", "be"},
	"uk_nin":         {"a", "b", "c", "d"},
	"eu_vat":         {"at", "be", "bg", "cy", "cz", "de", "dk", "ee", "el", "es", "fi", "fr", "hr", "hu", "ie", "it", "lt", "lu", "lv", "mt", "nl", "pl", "pt", "ro", "se", "si", "sk"},
	"india_aadhaar":  {" "},
	"china_id":       {"x"},
}

var safePatternTokenBytes = normalizeTokenBytes(safePatternTokens)

type contentStats struct {
	digitCount int
	alphaCount int
	spaceCount int
}

func scanContentStats(content []byte) contentStats {
	var stats contentStats
	for _, ch := range content {
		switch {
		case ch >= '0' && ch <= '9':
			stats.digitCount++
		case (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z'):
			stats.alphaCount++
		case ch == ' ' || ch == '\t':
			stats.spaceCount++
		}
	}
	return stats
}

func passesSafeShapeGate(name string, stats contentStats) bool {
	switch name {
	case "credit_card":
		return stats.digitCount >= 13
	case "ssn":
		return stats.digitCount >= 9
	case "ip_address":
		return stats.digitCount >= 4
	case "phone_number":
		return stats.digitCount >= 10
	case "street_address":
		return stats.digitCount >= 1 && stats.spaceCount > 0
	case "iban":
		return stats.alphaCount >= 2 && stats.digitCount >= 2 && (stats.alphaCount+stats.digitCount) >= 15
	case "uk_nin":
		return stats.alphaCount >= 2 && stats.digitCount >= 6
	case "eu_vat":
		return stats.alphaCount >= 2 && (stats.alphaCount+stats.digitCount) >= 8
	case "india_aadhaar":
		return stats.digitCount >= 12
	case "china_id":
		return stats.digitCount >= 17
	default:
		return true
	}
}

func normalizeTokenBytes(input map[string][]string) map[string][][]byte {
	normalized := make(map[string][][]byte, len(input))
	for name, tokens := range input {
		for _, token := range tokens {
			token = strings.TrimSpace(token)
			if token == "" {
				continue
			}
			normalized[name] = append(normalized[name], []byte(token))
		}
	}
	return normalized
}

func aggressiveGate(lowerContent string, patternNames []string) SensitiveGate {
	tokenSet := make(map[string]struct{})
	patternToTokens := make(map[string][]string, len(patternNames))
	for _, name := range patternNames {
		tokens, ok := aggressivePatternTokens[name]
		if !ok || len(tokens) == 0 {
			continue
		}
		patternToTokens[name] = tokens
		for _, token := range tokens {
			token = strings.ToLower(strings.TrimSpace(token))
			if token == "" {
				continue
			}
			tokenSet[token] = struct{}{}
		}
	}

	if len(tokenSet) == 0 {
		return SensitiveGate{allowAll: true}
	}

	tokens := make([]string, 0, len(tokenSet))
	for token := range tokenSet {
		tokens = append(tokens, token)
	}
	matcher := ahocorasick.NewStringMatcher(tokens)
	matches := matcher.MatchThreadSafe([]byte(lowerContent))

	matchedTokens := make(map[string]bool, len(matches))
	for _, idx := range matches {
		if idx < 0 || idx >= len(tokens) {
			continue
		}
		matchedTokens[tokens[idx]] = true
	}

	allowed := make(map[string]bool, len(patternNames))
	for _, name := range patternNames {
		tokens, ok := patternToTokens[name]
		if !ok {
			allowed[name] = true
			continue
		}
		for _, token := range tokens {
			token = strings.ToLower(strings.TrimSpace(token))
			if matchedTokens[token] {
				allowed[name] = true
				break
			}
		}
	}
	return SensitiveGate{allowed: allowed}
}

func containsAnyToken(content string, tokens []string, caseInsensitive bool) bool {
	for _, token := range tokens {
		token = strings.TrimSpace(token)
		if token == "" {
			continue
		}
		if caseInsensitive {
			if tokenContainsFoldASCII(content, token) {
				return true
			}
			continue
		}
		if tokenContains(content, token) {
			return true
		}
	}
	return false
}

func containsAnyTokenBytes(content []byte, tokens [][]byte, caseInsensitive bool) bool {
	for _, token := range tokens {
		if len(token) == 0 {
			continue
		}
		if caseInsensitive {
			if tokenContainsFoldASCIIBytes(content, token) {
				return true
			}
			continue
		}
		if bytes.Contains(content, token) {
			return true
		}
	}
	return false
}

func tokenContainsFoldASCII(content, token string) bool {
	if token == "" {
		return true
	}
	n := len(token)
	if n > len(content) {
		return false
	}
	first := toASCIILower(token[0])
	limit := len(content) - n
	for i := 0; i <= limit; i++ {
		if toASCIILower(content[i]) != first {
			continue
		}
		matched := true
		for j := 1; j < n; j++ {
			if toASCIILower(content[i+j]) != toASCIILower(token[j]) {
				matched = false
				break
			}
		}
		if matched {
			return true
		}
	}
	return false
}

func tokenContainsFoldASCIIBytes(content, token []byte) bool {
	if len(token) == 0 {
		return true
	}
	n := len(token)
	if n > len(content) {
		return false
	}
	first := toASCIILower(token[0])
	limit := len(content) - n
	for i := 0; i <= limit; i++ {
		if toASCIILower(content[i]) != first {
			continue
		}
		matched := true
		for j := 1; j < n; j++ {
			if toASCIILower(content[i+j]) != toASCIILower(token[j]) {
				matched = false
				break
			}
		}
		if matched {
			return true
		}
	}
	return false
}

func toASCIILower(b byte) byte {
	if b >= 'A' && b <= 'Z' {
		return b + ('a' - 'A')
	}
	return b
}

func normalizeTerms(terms []string) []string {
	seen := make(map[string]struct{}, len(terms))
	normalized := make([]string, 0, len(terms))
	for _, term := range terms {
		term = strings.TrimSpace(term)
		if term == "" {
			continue
		}
		if _, ok := seen[term]; ok {
			continue
		}
		seen[term] = struct{}{}
		normalized = append(normalized, term)
	}
	return normalized
}
