package scanner

import "regexp"

var sensitivePatterns = map[string]*regexp.Regexp{
	"email":          regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`),
	"credit_card":    regexp.MustCompile(`\b(?:\d[ -]*?){13,16}\b`),
	"ssn":            regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`),
	"ip_address":     regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`),
	"api_key":        regexp.MustCompile(`(?i)(api_key|api-secret|access-token)[\s:=]+"?[\w\-]+"?`),
	"phone_number":   regexp.MustCompile(`\b\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b`),
	"aws_access_key": regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
	"jwt_token":      regexp.MustCompile(`eyJ[\w-]+?\.[\w-]+?\.[\w-]+`),
	"street_address": regexp.MustCompile(`\b\d{1,5}\s+[A-Za-z0-9]+(?:\s+[A-Za-z0-9]+)*\s+(?:Street|St|Avenue|Ave|Boulevard|Blvd|Road|Rd|Lane|Ln|Drive|Dr)\b`),
	"iban":           regexp.MustCompile(`\b[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}\b`),
	"uk_nin":         regexp.MustCompile(`\b[A-CEGHJ-PR-TW-Z]{2}\d{6}[A-D]\b`),
	"eu_vat":         regexp.MustCompile(`\b[A-Z]{2}[0-9A-Z]{8,12}\b`),
	"india_aadhaar":  regexp.MustCompile(`\b\d{4}\s?\d{4}\s?\d{4}\b`),
	"china_id":       regexp.MustCompile(`\b\d{17}[0-9Xx]\b`),
}

func GetPatterns(types []string, custom map[string]string, exclude []string) map[string]*regexp.Regexp {
	patterns := make(map[string]*regexp.Regexp)

	available := make(map[string]*regexp.Regexp)
	for k, v := range sensitivePatterns {
		available[k] = v
	}
	if custom != nil {
		for name, regex := range custom {
			if compiled, err := regexp.Compile(regex); err == nil {
				available[name] = compiled
			}
		}
	}

	selected := make(map[string]bool)
	if len(types) == 0 {
		if len(exclude) > 0 {
			for name := range available {
				selected[name] = true
			}
		}
	} else {
		for _, t := range types {
			if t == "all" {
				for name := range available {
					selected[name] = true
				}
			} else if _, exists := available[t]; exists {
				selected[t] = true
			}
		}
	}

	for _, ex := range exclude {
		delete(selected, ex)
	}

	for name := range selected {
		patterns[name] = available[name]
	}
	return patterns
}
