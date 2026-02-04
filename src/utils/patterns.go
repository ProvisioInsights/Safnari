package utils

import (
	"path/filepath"
	"regexp"
)

type PatternMatcher struct {
	includeGlobs []string
	includeRegex []*regexp.Regexp
	excludeGlobs []string
	excludeRegex []*regexp.Regexp
}

func NewPatternMatcher(includePatterns, excludePatterns []string) *PatternMatcher {
	return &PatternMatcher{
		includeGlobs: append([]string(nil), includePatterns...),
		includeRegex: compileRegex(includePatterns),
		excludeGlobs: append([]string(nil), excludePatterns...),
		excludeRegex: compileRegex(excludePatterns),
	}
}

func (m *PatternMatcher) ShouldInclude(path string) bool {
	if m == nil {
		return true
	}
	if (len(m.includeGlobs) > 0 || len(m.includeRegex) > 0) && !m.matches(path, m.includeGlobs, m.includeRegex) {
		return false
	}
	if (len(m.excludeGlobs) > 0 || len(m.excludeRegex) > 0) && m.matches(path, m.excludeGlobs, m.excludeRegex) {
		return false
	}
	return true
}

func (m *PatternMatcher) matches(path string, globs []string, regexes []*regexp.Regexp) bool {
	for _, pattern := range globs {
		matched, _ := filepath.Match(pattern, filepath.Base(path))
		if matched {
			return true
		}
	}
	for _, re := range regexes {
		if re.MatchString(path) {
			return true
		}
	}
	return false
}

func compileRegex(patterns []string) []*regexp.Regexp {
	compiled := make([]*regexp.Regexp, 0, len(patterns))
	for _, pattern := range patterns {
		if re, err := regexp.Compile(pattern); err == nil {
			compiled = append(compiled, re)
		}
	}
	return compiled
}
