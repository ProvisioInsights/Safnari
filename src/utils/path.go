package utils

import (
	"path/filepath"
	"strings"
	"sync"
)

// IsPathWithin returns true if the given path is within any of the roots.
func IsPathWithin(path string, roots []string) bool {
	return getPathGuard(roots).Contains(path)
}

type pathGuard struct {
	roots []string
}

var pathGuardCache sync.Map

func getPathGuard(roots []string) *pathGuard {
	key := strings.Join(roots, "\x00")
	if cached, ok := pathGuardCache.Load(key); ok {
		return cached.(*pathGuard)
	}

	normalizedRoots := make([]string, 0, len(roots))
	for _, root := range roots {
		if root == "" {
			continue
		}
		absRoot, err := filepath.Abs(root)
		if err != nil {
			continue
		}
		normalizedRoots = append(normalizedRoots, filepath.Clean(absRoot))
	}
	guard := &pathGuard{roots: normalizedRoots}
	actual, _ := pathGuardCache.LoadOrStore(key, guard)
	return actual.(*pathGuard)
}

func (g *pathGuard) Contains(path string) bool {
	if g == nil {
		return false
	}
	absPath, err := filepath.Abs(path)
	if err != nil {
		return false
	}
	absPath = filepath.Clean(absPath)

	for _, absRoot := range g.roots {
		rel, err := filepath.Rel(absRoot, absPath)
		if err != nil {
			continue
		}
		if rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))) {
			return true
		}
	}
	return false
}
