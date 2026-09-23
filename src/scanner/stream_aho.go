package scanner

import "bytes"

type ahoNode struct {
	next map[byte]int
	fail int
	out  []int
}

type streamAhoMatcher struct {
	terms    []string
	patterns [][]byte
	nodes    []ahoNode
	// transitions avoids per-byte map lookups for small search automata.
	// Large term sets retain the sparse representation to bound memory.
	transitions []uint32
	state       int
	lastEnd     []int64
	processed   int64
}

type streamAhoCounter struct {
	matcher *streamAhoMatcher
	counts  []int
	maxLen  int
	tail    []byte
	seen    int64
	decided bool
}

const maxByteSearchTerms = 4
const maxByteSearchPattern = 64

func byteSearchMaxLen(patterns [][]byte) int {
	if len(patterns) == 0 || len(patterns) > maxByteSearchTerms {
		return 0
	}
	maxLen := 0
	for _, pattern := range patterns {
		if len(pattern) == 0 || len(pattern) > maxByteSearchPattern {
			return 0
		}
		maxLen = max(maxLen, len(pattern))
	}
	return maxLen
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
	matcher.buildTransitions()
	return matcher
}

func newStreamAhoCounter(terms []string) *streamAhoCounter {
	matcher := newStreamAhoMatcher(terms)
	return &streamAhoCounter{
		matcher: matcher,
		counts:  make([]int, len(matcher.terms)),
		maxLen:  byteSearchMaxLen(matcher.patterns),
	}
}

func newStreamAhoCounterFromTemplate(template *streamAhoMatcher) *streamAhoCounter {
	matcher := &streamAhoMatcher{
		terms:       template.terms,
		patterns:    template.patterns,
		nodes:       template.nodes,
		transitions: template.transitions,
		lastEnd:     make([]int64, len(template.terms)),
	}
	maxLen := byteSearchMaxLen(template.patterns)
	return &streamAhoCounter{matcher: matcher, counts: make([]int, len(template.terms)), maxLen: maxLen}
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

func (m *streamAhoMatcher) buildTransitions() {
	const maxDenseNodes = 256
	if len(m.nodes) > maxDenseNodes {
		return
	}
	m.transitions = make([]uint32, len(m.nodes)*256)
	queue := make([]int, 0, len(m.nodes)-1)
	for b, next := range m.nodes[0].next {
		m.transitions[int(b)] = uint32(next)
		queue = append(queue, next)
	}
	for head := 0; head < len(queue); head++ {
		node := queue[head]
		row := m.transitions[node*256 : (node+1)*256]
		copy(row, m.transitions[m.nodes[node].fail*256:(m.nodes[node].fail+1)*256])
		for b, next := range m.nodes[node].next {
			row[int(b)] = uint32(next)
			queue = append(queue, next)
		}
	}
	for i := range m.nodes {
		m.nodes[i].next = nil
	}
}

func (m *streamAhoMatcher) Consume(chunk []byte, emit func(index int, start, end int64)) {
	if m == nil || len(m.terms) == 0 {
		return
	}
	if len(m.transitions) != 0 {
		for i, b := range chunk {
			m.state = int(m.transitions[m.state*256+int(b)])
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
	if !c.decided {
		c.decided = true
		if c.maxLen != 0 && len(chunk) >= 16*1024 {
			sample := chunk[:min(len(chunk), 4096)]
			hits := 0
			for _, pattern := range c.matcher.patterns {
				hits += bytes.Count(sample, pattern)
			}
			if hits > len(sample)/64 {
				c.maxLen = 0
			}
		}
	}
	if c.maxLen != 0 {
		c.consumeByteSearch(chunk)
		return
	}
	c.matcher.Consume(chunk, func(index int, _, _ int64) {
		c.counts[index]++
	})
}

func (c *streamAhoCounter) consumeByteSearch(chunk []byte) {
	var edge [2 * maxByteSearchPattern]byte
	prefix := min(len(chunk), c.maxLen-1)
	copy(edge[:], c.tail)
	copy(edge[len(c.tail):], chunk[:prefix])
	boundary := edge[:len(c.tail)+prefix]
	boundaryStart := c.seen - int64(len(c.tail))
	for index, pattern := range c.matcher.patterns {
		lastEnd := c.matcher.lastEnd[index]
		for pos := 0; pos+len(pattern) <= len(boundary); {
			found := bytes.Index(boundary[pos:], pattern)
			if found < 0 {
				break
			}
			start := boundaryStart + int64(pos+found)
			end := start + int64(len(pattern))
			if start >= lastEnd {
				c.counts[index]++
				lastEnd = end
				pos += found + len(pattern)
			} else {
				pos += found + 1
			}
		}
		start := max(int64(0), lastEnd-c.seen)
		for pos := int(start); pos+len(pattern) <= len(chunk); {
			found := bytes.Index(chunk[pos:], pattern)
			if found < 0 {
				break
			}
			end := c.seen + int64(pos+found+len(pattern))
			c.counts[index]++
			lastEnd = end
			pos += found + len(pattern)
		}
		c.matcher.lastEnd[index] = lastEnd
	}
	c.seen += int64(len(chunk))
	keep := c.maxLen - 1
	if keep <= 0 {
		return
	}
	if len(chunk) >= keep {
		c.tail = append(c.tail[:0], chunk[len(chunk)-keep:]...)
		return
	}
	if len(c.tail)+len(chunk) > keep {
		c.tail = append(c.tail[:0], c.tail[len(c.tail)+len(chunk)-keep:]...)
	}
	c.tail = append(c.tail, chunk...)
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
