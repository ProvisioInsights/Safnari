package prefilter

import "strings"

func tokenContainsGeneric(content, token string) bool {
	return strings.Contains(content, token)
}
