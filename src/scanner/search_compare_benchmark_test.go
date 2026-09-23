package scanner

import (
	"strings"
	"testing"
)

func BenchmarkStreamSearchAlgorithms(b *testing.B) {
	cases := []struct {
		name  string
		terms []string
		data  []byte
	}{
		{
			name:  "repeated_log",
			terms: []string{"ALPHA", "email"},
			data:  []byte(strings.Repeat("ALPHA user@example.com email\n", 8192)),
		},
		{
			name:  "repeated_prefix",
			terms: []string{"aaaaab", "baa"},
			data:  []byte(strings.Repeat("a", 256*1024)),
		},
	}
	for _, corpus := range cases {
		template := newStreamAhoMatcher(corpus.terms)
		b.Run(corpus.name+"/automaton", func(b *testing.B) {
			for range b.N {
				matcher := &streamAhoMatcher{
					terms: template.terms, patterns: template.patterns, nodes: template.nodes,
					transitions: template.transitions, lastEnd: make([]int64, len(template.terms)),
				}
				counts := make([]int, len(template.terms))
				matcher.Consume(corpus.data, func(index int, _, _ int64) { counts[index]++ })
			}
		})
		b.Run(corpus.name+"/byte_search", func(b *testing.B) {
			for range b.N {
				counter := newStreamAhoCounterFromTemplate(template)
				counter.Consume(corpus.data)
			}
		})
	}
}
