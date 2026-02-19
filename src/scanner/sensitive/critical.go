package sensitive

import "bytes"

func IsCriticalPattern(name string) bool {
	switch name {
	case "email", "credit_card", "ssn", "api_key", "aws_access_key", "jwt_token":
		return true
	default:
		return false
	}
}

func ScanDeterministic(content []byte, pattern string, limit int) []string {
	if limit == 0 {
		return nil
	}
	switch pattern {
	case "email":
		return scanEmails(content, limit)
	case "credit_card":
		return scanCreditCards(content, limit)
	case "ssn":
		return scanSSN(content, limit)
	case "api_key":
		return scanAPIKeys(content, limit)
	case "aws_access_key":
		return scanAWSAccessKeys(content, limit)
	case "jwt_token":
		return scanJWT(content, limit)
	default:
		return nil
	}
}

func scanEmails(content []byte, limit int) []string {
	var out []string
	for i := 0; i < len(content); i++ {
		if content[i] != '@' {
			continue
		}
		start := i - 1
		for start >= 0 && isEmailLocal(content[start]) {
			start--
		}
		start++
		end := i + 1
		for end < len(content) && isEmailDomain(content[end]) {
			end++
		}
		if start >= i || end <= i+1 {
			continue
		}
		candidate := content[start:end]
		at := bytes.IndexByte(candidate, '@')
		if at <= 0 || at >= len(candidate)-1 {
			continue
		}
		domain := candidate[at+1:]
		dot := bytes.LastIndexByte(domain, '.')
		if dot <= 0 || dot >= len(domain)-2 {
			continue
		}
		if !isAlphabeticBytes(domain[dot+1:]) {
			continue
		}
		out = append(out, string(candidate))
		if limit > 0 && len(out) >= limit {
			break
		}
		i = end
	}
	return out
}

func scanCreditCards(content []byte, limit int) []string {
	var out []string
	i := 0
	for i < len(content) {
		if !isDigit(content[i]) {
			i++
			continue
		}
		start := i
		end := i
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
		if digits >= 13 && digits <= 16 && end > start {
			candidate := content[start:end]
			if luhnValid(candidate) {
				out = append(out, string(candidate))
				if limit > 0 && len(out) >= limit {
					break
				}
			}
		}
		i = end + 1
	}
	return out
}

func scanSSN(content []byte, limit int) []string {
	var out []string
	for i := 0; i+10 < len(content); i++ {
		if !(isDigit(content[i]) && isDigit(content[i+1]) && isDigit(content[i+2]) &&
			content[i+3] == '-' &&
			isDigit(content[i+4]) && isDigit(content[i+5]) &&
			content[i+6] == '-' &&
			isDigit(content[i+7]) && isDigit(content[i+8]) && isDigit(content[i+9]) && isDigit(content[i+10])) {
			continue
		}
		out = append(out, string(content[i:i+11]))
		if limit > 0 && len(out) >= limit {
			break
		}
		i += 10
	}
	return out
}

func scanAPIKeys(content []byte, limit int) []string {
	var out []string
	lower := bytes.ToLower(content)
	tokens := [][]byte{[]byte("api_key"), []byte("api-secret"), []byte("access-token")}
	for _, token := range tokens {
		offset := 0
		for {
			idx := bytes.Index(lower[offset:], token)
			if idx < 0 {
				break
			}
			start := offset + idx
			pos := start + len(token)
			for pos < len(content) && (content[pos] == ' ' || content[pos] == '\t') {
				pos++
			}
			if pos >= len(content) || (content[pos] != ':' && content[pos] != '=') {
				offset = start + 1
				continue
			}
			pos++
			for pos < len(content) && (content[pos] == ' ' || content[pos] == '\t') {
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
				offset = start + 1
				continue
			}
			if quoted && pos < len(content) && content[pos] == '"' {
				pos++
			}
			out = append(out, string(content[start:pos]))
			if limit > 0 && len(out) >= limit {
				return out
			}
			offset = start + 1
		}
	}
	return dedupe(out, limit)
}

func scanAWSAccessKeys(content []byte, limit int) []string {
	var out []string
	for i := 0; i+20 <= len(content); i++ {
		if !(content[i] == 'A' && content[i+1] == 'K' && content[i+2] == 'I' && content[i+3] == 'A') {
			continue
		}
		ok := true
		for j := i + 4; j < i+20; j++ {
			if !isUpperOrDigit(content[j]) {
				ok = false
				break
			}
		}
		if !ok {
			continue
		}
		out = append(out, string(content[i:i+20]))
		if limit > 0 && len(out) >= limit {
			break
		}
		i += 19
	}
	return out
}

func scanJWT(content []byte, limit int) []string {
	var out []string
	for i := 0; i+6 < len(content); i++ {
		if !(content[i] == 'e' && content[i+1] == 'y' && content[i+2] == 'J') {
			continue
		}
		j := i
		seg1End := scanJWTSegment(content, j)
		if seg1End <= j || seg1End >= len(content) || content[seg1End] != '.' {
			continue
		}
		j = seg1End + 1
		seg2End := scanJWTSegment(content, j)
		if seg2End <= j || seg2End >= len(content) || content[seg2End] != '.' {
			continue
		}
		j = seg2End + 1
		seg3End := scanJWTSegment(content, j)
		if seg3End <= j {
			continue
		}
		out = append(out, string(content[i:seg3End]))
		if limit > 0 && len(out) >= limit {
			break
		}
		i = seg3End
	}
	return out
}

func scanJWTSegment(content []byte, start int) int {
	i := start
	for i < len(content) && isJWTChar(content[i]) {
		i++
	}
	return i
}

func luhnValid(number []byte) bool {
	var digitCount int
	for _, ch := range number {
		switch ch {
		case ' ', '-':
			continue
		default:
			if ch < '0' || ch > '9' {
				return false
			}
			digitCount++
		}
	}
	if digitCount < 13 || digitCount > 16 {
		return false
	}

	var sum int
	alt := false
	for i := len(number) - 1; i >= 0; i-- {
		ch := number[i]
		if ch == ' ' || ch == '-' {
			continue
		}
		d := int(ch - '0')
		if alt {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		alt = !alt
	}
	return sum%10 == 0
}

func dedupe(values []string, limit int) []string {
	if len(values) < 2 {
		return values
	}
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out
}

func isDigit(ch byte) bool {
	return ch >= '0' && ch <= '9'
}

func isUpperOrDigit(ch byte) bool {
	return (ch >= 'A' && ch <= 'Z') || isDigit(ch)
}

func isEmailLocal(ch byte) bool {
	return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || isDigit(ch) ||
		ch == '.' || ch == '_' || ch == '%' || ch == '+' || ch == '-'
}

func isEmailDomain(ch byte) bool {
	return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || isDigit(ch) ||
		ch == '.' || ch == '-'
}

func isAlphabeticBytes(value []byte) bool {
	for _, ch := range value {
		if !((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z')) {
			return false
		}
	}
	return len(value) > 0
}

func isWordLike(ch byte) bool {
	return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || isDigit(ch) || ch == '_' || ch == '-'
}

func isJWTChar(ch byte) bool {
	return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || isDigit(ch) || ch == '_' || ch == '-'
}
