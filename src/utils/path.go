package utils

import (
	"path/filepath"
	"strings"
)

// IsPathWithin returns true if the given path is within any of the roots.
func IsPathWithin(path string, roots []string) bool {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		resolved = path
	}
	absPath, err := filepath.Abs(resolved)
	if err != nil {
		return false
	}
	for _, root := range roots {
		rResolved, err := filepath.EvalSymlinks(root)
		if err != nil {
			rResolved = root
		}
		absRoot, err := filepath.Abs(rResolved)
		if err != nil {
			continue
		}
		rel, err := filepath.Rel(absRoot, absPath)
		if err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return true
		}
	}
	return false
}
