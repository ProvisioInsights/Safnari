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
		normalizedRoots = append(normalizedRoots, canonicalPath(absRoot))
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
	absPath = canonicalPath(absPath)

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

func canonicalPath(path string) string {
	cleaned := filepath.Clean(path)
	resolved, err := filepath.EvalSymlinks(cleaned)
	if err != nil {
		return canonicalExistingPrefix(cleaned)
	}
	return filepath.Clean(resolved)
}

func canonicalExistingPrefix(path string) string {
	volume := filepath.VolumeName(path)
	rest := strings.TrimPrefix(path, volume)
	rest = strings.Trim(rest, string(filepath.Separator))
	if rest == "" {
		return path
	}
	parts := strings.Split(rest, string(filepath.Separator))
	for i := len(parts); i > 0; i-- {
		prefix := volume + string(filepath.Separator) + filepath.Join(parts[:i]...)
		if volume == "" {
			prefix = string(filepath.Separator) + filepath.Join(parts[:i]...)
		}
		resolved, err := filepath.EvalSymlinks(prefix)
		if err != nil {
			continue
		}
		if i == len(parts) {
			return filepath.Clean(resolved)
		}
		return filepath.Clean(filepath.Join(append([]string{resolved}, parts[i:]...)...))
	}
	return path
}
