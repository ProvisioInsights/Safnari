package fuzzy

import "strings"

// Hasher defines a fuzzy hashing implementation.
type Hasher interface {
	Name() string
	HashFile(path string) (string, error)
}

var registry = map[string]Hasher{}

// Register adds a fuzzy hasher to the registry.
func Register(hasher Hasher) {
	if hasher == nil {
		return
	}
	registry[strings.ToLower(hasher.Name())] = hasher
}

// Lookup returns a registered hasher by name.
func Lookup(name string) (Hasher, bool) {
	hasher, ok := registry[strings.ToLower(name)]
	return hasher, ok
}

// Available returns the names of registered hashers.
func Available() []string {
	names := make([]string, 0, len(registry))
	for name := range registry {
		names = append(names, name)
	}
	return names
}
