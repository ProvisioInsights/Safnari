package scanner

import (
	"fmt"
	"math/rand"
	"strings"
	"testing"
)

func TestStreamAhoDenseAndSparseCountsAcrossChunks(t *testing.T) {
	text := strings.Repeat("ababa XYZ café ", 19) + "term-299 ababa"
	for _, terms := range [][]string{
		{"a", "aba", "ababa", "XYZ", "café", "missing"},
		func() []string {
			many := make([]string, 300)
			for i := range many {
				many[i] = fmt.Sprintf("term-%03d", i)
			}
			return many
		}(),
	} {
		for _, chunkSize := range []int{1, 7, 4096} {
			counter := newStreamAhoCounter(terms)
			if gotDense := len(counter.matcher.transitions) != 0; gotDense != (len(terms) < 300) {
				t.Fatalf("unexpected automaton representation for %d terms", len(terms))
			}
			for offset := 0; offset < len(text); offset += chunkSize {
				end := min(offset+chunkSize, len(text))
				counter.Consume([]byte(text[offset:end]))
			}
			got := counter.Results()
			for _, term := range terms {
				want := strings.Count(text, term)
				if got[term] != want {
					t.Fatalf("term=%q chunk=%d: got=%d want=%d", term, chunkSize, got[term], want)
				}
			}
		}
	}
}

func TestStreamByteSearchMatchesAutomatonAcrossChunks(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	for trial := range 200 {
		terms := []string{"a", "aba", "aa", "café"}
		if trial%2 == 0 {
			terms = []string{"ababa", "ba", "bb"}
		}
		var content strings.Builder
		for range 160 {
			content.WriteByte("aabbbeé"[rng.Intn(len("aabbbeé"))])
		}
		content.WriteString(" café ababa aba aaaa café ")
		data := []byte(content.String())
		counter := newStreamAhoCounter(terms)
		if counter.maxLen == 0 {
			t.Fatal("short term set did not select byte search")
		}
		ref := newStreamAhoMatcher(terms)
		want := make([]int, len(ref.terms))
		for offset := 0; offset < len(data); {
			step := 1 + rng.Intn(17)
			end := min(offset+step, len(data))
			chunk := data[offset:end]
			counter.Consume(chunk)
			ref.Consume(chunk, func(index int, _, _ int64) { want[index]++ })
			offset = end
		}
		for i, got := range counter.counts {
			if got != want[i] {
				t.Fatalf("trial=%d term=%q: byte search=%d automaton=%d", trial, counter.matcher.terms[i], got, want[i])
			}
		}
	}
}

func TestStreamSearchUsesAutomatonForDenseLargeChunks(t *testing.T) {
	dense := newStreamAhoCounter([]string{"ALPHA", "email"})
	dense.Consume([]byte(strings.Repeat("ALPHA email\n", 2000)))
	if dense.maxLen != 0 {
		t.Fatal("dense search terms did not use the automaton")
	}
	if dense.Results()["ALPHA"] != 2000 || dense.Results()["email"] != 2000 {
		t.Fatalf("dense match counts changed: %v", dense.Results())
	}
	sparse := newStreamAhoCounter([]string{"ALPHA", "email"})
	sparse.Consume([]byte(strings.Repeat("unrelated text\n", 2000)))
	if sparse.maxLen == 0 {
		t.Fatal("sparse search terms did not use byte search")
	}
}

func TestStreamAhoTemplateKeepsPerFileStateSeparate(t *testing.T) {
	template := newStreamAhoMatcher([]string{"ALPHA", "email"})
	first := newStreamAhoCounterFromTemplate(template)
	second := newStreamAhoCounterFromTemplate(template)
	first.Consume([]byte("AL"))
	second.Consume([]byte("email"))
	first.Consume([]byte("PHA"))
	if got := first.Results()["ALPHA"]; got != 1 {
		t.Fatalf("first file lost cross-chunk match: %d", got)
	}
	if got := second.Results()["email"]; got != 1 {
		t.Fatalf("second file changed by first: %d", got)
	}
}
