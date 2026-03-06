package scanner

type ahoNode struct {
	next map[byte]int
	fail int
	out  []int
}

type streamAhoMatcher struct {
	terms     []string
	patterns  [][]byte
	nodes     []ahoNode
	state     int
	lastEnd   []int64
	processed int64
}

type streamAhoCounter struct {
	matcher *streamAhoMatcher
	counts  []int
}

func newStreamAhoMatcher(terms []string) *streamAhoMatcher {
	normalized := normalizeSearchTerms(terms)
	if len(normalized) == 0 {
		return &streamAhoMatcher{}
	}

	matcher := &streamAhoMatcher{
		terms:    normalized,
		patterns: make([][]byte, len(normalized)),
		nodes:    []ahoNode{{next: make(map[byte]int)}},
		lastEnd:  make([]int64, len(normalized)),
	}
	for i := range normalized {
		matcher.patterns[i] = []byte(normalized[i])
		matcher.addPattern(i, matcher.patterns[i])
	}
	matcher.buildFailures()
	return matcher
}

func newStreamAhoCounter(terms []string) *streamAhoCounter {
	matcher := newStreamAhoMatcher(terms)
	return &streamAhoCounter{
		matcher: matcher,
		counts:  make([]int, len(matcher.terms)),
	}
}

func (m *streamAhoMatcher) addPattern(index int, pattern []byte) {
	node := 0
	for _, b := range pattern {
		next, ok := m.nodes[node].next[b]
		if !ok {
			next = len(m.nodes)
			m.nodes = append(m.nodes, ahoNode{next: make(map[byte]int)})
			m.nodes[node].next[b] = next
		}
		node = next
	}
	m.nodes[node].out = append(m.nodes[node].out, index)
}

func (m *streamAhoMatcher) buildFailures() {
	queue := make([]int, 0, len(m.nodes))
	for _, next := range m.nodes[0].next {
		queue = append(queue, next)
	}
	for len(queue) > 0 {
		node := queue[0]
		queue = queue[1:]
		for b, next := range m.nodes[node].next {
			queue = append(queue, next)
			fail := m.nodes[node].fail
			for fail != 0 {
				if candidate, ok := m.nodes[fail].next[b]; ok {
					fail = candidate
					break
				}
				fail = m.nodes[fail].fail
			}
			if fail == 0 {
				if candidate, ok := m.nodes[0].next[b]; ok && candidate != next {
					m.nodes[next].fail = candidate
				}
			} else {
				m.nodes[next].fail = fail
			}
			m.nodes[next].out = append(m.nodes[next].out, m.nodes[m.nodes[next].fail].out...)
		}
	}
}

func (m *streamAhoMatcher) Consume(chunk []byte, emit func(index int, start, end int64)) {
	if m == nil || len(m.terms) == 0 {
		return
	}
	for i, b := range chunk {
		for m.state != 0 {
			if _, ok := m.nodes[m.state].next[b]; ok {
				break
			}
			m.state = m.nodes[m.state].fail
		}
		if next, ok := m.nodes[m.state].next[b]; ok {
			m.state = next
		}

		end := m.processed + int64(i) + 1
		for _, matchIndex := range m.nodes[m.state].out {
			start := end - int64(len(m.patterns[matchIndex]))
			if start < m.lastEnd[matchIndex] {
				continue
			}
			m.lastEnd[matchIndex] = end
			if emit != nil {
				emit(matchIndex, start, end)
			}
		}
	}
	m.processed += int64(len(chunk))
}

func (c *streamAhoCounter) Consume(chunk []byte) {
	if c == nil || c.matcher == nil || len(c.matcher.terms) == 0 {
		return
	}
	c.matcher.Consume(chunk, func(index int, _, _ int64) {
		c.counts[index]++
	})
}

func (c *streamAhoCounter) Results() map[string]int {
	if c == nil || c.matcher == nil || len(c.matcher.terms) == 0 {
		return nil
	}
	var hits map[string]int
	for i, count := range c.counts {
		if count <= 0 {
			continue
		}
		if hits == nil {
			hits = make(map[string]int, len(c.matcher.terms))
		}
		hits[c.matcher.terms[i]] = count
	}
	return hits
}
