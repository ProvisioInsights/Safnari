package sensitive

type Match struct {
	Pattern string
	Value   string
	Start   int
	End     int
}

func ScanDeterministicAll(
	content []byte,
	patternNames []string,
	maxPerType, maxTotal int,
) (map[string][]string, map[string]int) {
	matches := ScanDeterministicMatches(content, patternNames, maxPerType, maxTotal)
	if len(matches) == 0 {
		return nil, nil
	}
	out := make(map[string][]string, len(patternNames))
	counts := make(map[string]int, len(patternNames))
	for _, m := range matches {
		out[m.Pattern] = append(out[m.Pattern], m.Value)
		counts[m.Pattern]++
	}
	return out, counts
}

func ScanDeterministicMatches(
	content []byte,
	patternNames []string,
	maxPerType, maxTotal int,
) []Match {
	if len(content) == 0 || len(patternNames) == 0 {
		return nil
	}

	enabled := enabledCriticalPatterns(patternNames)
	if !enabled.any() {
		return nil
	}

	perTypeLimited := maxPerType > 0
	totalLimited := maxTotal > 0
	perTypeCounts := make(map[string]int, len(patternNames))
	apiKeySeen := make(map[string]struct{}, 8)
	matches := make([]Match, 0, 16)

	add := func(pattern string, start, end int) bool {
		if start < 0 || end <= start || end > len(content) {
			return false
		}
		if perTypeLimited && perTypeCounts[pattern] >= maxPerType {
			return false
		}
		if totalLimited && len(matches) >= maxTotal {
			return false
		}
		value := string(content[start:end])
		if pattern == "api_key" {
			if _, exists := apiKeySeen[value]; exists {
				return false
			}
			apiKeySeen[value] = struct{}{}
		}
		matches = append(matches, Match{
			Pattern: pattern,
			Value:   value,
			Start:   start,
			End:     end,
		})
		perTypeCounts[pattern]++
		return true
	}

	for i := 0; i < len(content); i++ {
		if totalLimited && len(matches) >= maxTotal {
			break
		}

		ch := content[i]

		if enabled.awsAccessKey && ch == 'A' {
			if end, ok := matchAWSAccessKeyAt(content, i); ok {
				add("aws_access_key", i, end)
				i = end - 1
				continue
			}
		}

		if enabled.jwtToken && ch == 'e' {
			if end, ok := matchJWTAt(content, i); ok {
				add("jwt_token", i, end)
				i = end - 1
				continue
			}
		}

		if enabled.email && ch == '@' {
			if start, end, ok := matchEmailAroundAt(content, i); ok {
				add("email", start, end)
				i = end - 1
				continue
			}
		}

		if enabled.apiKey && isASCIILetter(ch) {
			if end, ok := matchAPIKeyAt(content, i); ok {
				add("api_key", i, end)
				i = end - 1
				continue
			}
		}

		if !isDigit(ch) {
			continue
		}

		if enabled.ssn {
			if end, ok := matchSSNAt(content, i); ok {
				add("ssn", i, end)
				i = end - 1
				continue
			}
		}

		if enabled.creditCard {
			end, ok := matchCreditCardAt(content, i)
			if ok {
				add("credit_card", i, end)
			}
			if end > i {
				i = end - 1
			}
		}
	}

	return matches
}

type criticalPatternSet struct {
	email        bool
	creditCard   bool
	ssn          bool
	apiKey       bool
	awsAccessKey bool
	jwtToken     bool
}

func (s criticalPatternSet) any() bool {
	return s.email || s.creditCard || s.ssn || s.apiKey || s.awsAccessKey || s.jwtToken
}

func enabledCriticalPatterns(patternNames []string) criticalPatternSet {
	var enabled criticalPatternSet
	for _, name := range patternNames {
		switch name {
		case "email":
			enabled.email = true
		case "credit_card":
			enabled.creditCard = true
		case "ssn":
			enabled.ssn = true
		case "api_key":
			enabled.apiKey = true
		case "aws_access_key":
			enabled.awsAccessKey = true
		case "jwt_token":
			enabled.jwtToken = true
		}
	}
	return enabled
}

func matchEmailAroundAt(content []byte, at int) (start, end int, ok bool) {
	start = at - 1
	for start >= 0 && isEmailLocal(content[start]) {
		start--
	}
	start++
	end = at + 1
	for end < len(content) && isEmailDomain(content[end]) {
		end++
	}
	if start >= at || end <= at+1 {
		return 0, 0, false
	}
	candidate := content[start:end]
	localAt := -1
	for i, b := range candidate {
		if b == '@' {
			localAt = i
			break
		}
	}
	if localAt <= 0 || localAt >= len(candidate)-1 {
		return 0, 0, false
	}
	domain := candidate[localAt+1:]
	dot := -1
	for i := len(domain) - 1; i >= 0; i-- {
		if domain[i] == '.' {
			dot = i
			break
		}
	}
	if dot <= 0 || dot >= len(domain)-2 {
		return 0, 0, false
	}
	if !isAlphabeticBytes(domain[dot+1:]) {
		return 0, 0, false
	}
	return start, end, true
}

func matchCreditCardAt(content []byte, start int) (end int, ok bool) {
	end = start
	digits := 0
	for end < len(content) && (isDigit(content[end]) || content[end] == ' ' || content[end] == '-') {
		if isDigit(content[end]) {
			digits++
			if digits > 16 {
				break
			}
		}
		end++
	}
	for end > start && (content[end-1] == ' ' || content[end-1] == '-') {
		end--
	}
	if digits < 13 || digits > 16 || end <= start {
		return end, false
	}
	if !luhnValid(content[start:end]) {
		return end, false
	}
	return end, true
}

func matchSSNAt(content []byte, start int) (end int, ok bool) {
	if start+10 >= len(content) {
		return 0, false
	}
	if !(isDigit(content[start]) && isDigit(content[start+1]) && isDigit(content[start+2]) &&
		content[start+3] == '-' &&
		isDigit(content[start+4]) && isDigit(content[start+5]) &&
		content[start+6] == '-' &&
		isDigit(content[start+7]) && isDigit(content[start+8]) && isDigit(content[start+9]) && isDigit(content[start+10])) {
		return 0, false
	}
	return start + 11, true
}

func matchAWSAccessKeyAt(content []byte, start int) (end int, ok bool) {
	end = start + 20
	if end > len(content) {
		return 0, false
	}
	if !(content[start] == 'A' && content[start+1] == 'K' && content[start+2] == 'I' && content[start+3] == 'A') {
		return 0, false
	}
	for i := start + 4; i < end; i++ {
		if !isUpperOrDigit(content[i]) {
			return 0, false
		}
	}
	return end, true
}

func matchJWTAt(content []byte, start int) (end int, ok bool) {
	if start+6 >= len(content) {
		return 0, false
	}
	if !(content[start] == 'e' && content[start+1] == 'y' && content[start+2] == 'J') {
		return 0, false
	}
	seg1End := scanJWTSegment(content, start)
	if seg1End <= start || seg1End >= len(content) || content[seg1End] != '.' {
		return 0, false
	}
	seg2Start := seg1End + 1
	seg2End := scanJWTSegment(content, seg2Start)
	if seg2End <= seg2Start || seg2End >= len(content) || content[seg2End] != '.' {
		return 0, false
	}
	seg3Start := seg2End + 1
	seg3End := scanJWTSegment(content, seg3Start)
	if seg3End <= seg3Start {
		return 0, false
	}
	return seg3End, true
}

var apiKeyTokens = [...]string{"api_key", "api-secret", "access-token"}

func matchAPIKeyAt(content []byte, start int) (end int, ok bool) {
	var tokenLen int
	for _, token := range apiKeyTokens {
		if hasPrefixFoldASCII(content, start, token) {
			tokenLen = len(token)
			break
		}
	}
	if tokenLen == 0 {
		return 0, false
	}
	pos := start + tokenLen
	for pos < len(content) && isSpaceTab(content[pos]) {
		pos++
	}
	if pos >= len(content) || (content[pos] != ':' && content[pos] != '=') {
		return 0, false
	}
	pos++
	for pos < len(content) && isSpaceTab(content[pos]) {
		pos++
	}
	quoted := false
	if pos < len(content) && content[pos] == '"' {
		quoted = true
		pos++
	}
	valStart := pos
	for pos < len(content) && isWordLike(content[pos]) {
		pos++
	}
	if pos == valStart {
		return 0, false
	}
	if quoted && pos < len(content) && content[pos] == '"' {
		pos++
	}
	return pos, true
}

func hasPrefixFoldASCII(content []byte, start int, token string) bool {
	if start < 0 || start+len(token) > len(content) {
		return false
	}
	for i := 0; i < len(token); i++ {
		if lowerASCII(content[start+i]) != token[i] {
			return false
		}
	}
	return true
}

func lowerASCII(ch byte) byte {
	if ch >= 'A' && ch <= 'Z' {
		return ch + ('a' - 'A')
	}
	return ch
}

func isASCIILetter(ch byte) bool {
	return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z')
}

func isSpaceTab(ch byte) bool {
	return ch == ' ' || ch == '\t'
}
