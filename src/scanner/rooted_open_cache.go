package scanner

import (
	"os"
	"path/filepath"
	"sync"
)

const maxCachedDirectoryRoots = 64
const maxPendingFileCloses = 64

type cachedDirectoryRoot struct {
	root *os.Root
	refs int
	used uint64
}

// directoryRootCache retains a bounded number of directory capabilities. A
// worker holds a capability only until it has opened the file descriptor.
type directoryRootCache struct {
	anchor     *os.Root
	mu         sync.Mutex
	entries    map[string]*cachedDirectoryRoot
	clock      uint64
	closeQueue chan *os.File
	closerDone chan struct{}
}

func newDirectoryRootCache(anchor *os.Root) *directoryRootCache {
	c := &directoryRootCache{
		anchor:     anchor,
		entries:    make(map[string]*cachedDirectoryRoot),
		closeQueue: make(chan *os.File, maxPendingFileCloses),
		closerDone: make(chan struct{}),
	}
	go func() {
		for file := range c.closeQueue {
			_ = file.Close()
		}
		close(c.closerDone)
	}()
	return c
}

func (c *directoryRootCache) CloseFile(file *os.File) {
	if file != nil {
		c.closeQueue <- file
	}
}

func (c *directoryRootCache) Open(relativePath string) (*os.File, error) {
	dir, name := filepath.Split(relativePath)
	if dir == "" {
		return c.anchor.Open(name)
	}
	dir = filepath.Clean(dir)
	root, release, err := c.acquire(dir)
	if err != nil {
		return nil, err
	}
	file, err := root.Open(name)
	release()
	return file, err
}

func (c *directoryRootCache) acquire(dir string) (*os.Root, func(), error) {
	c.mu.Lock()
	c.clock++
	if entry := c.entries[dir]; entry != nil {
		entry.refs++
		entry.used = c.clock
		c.mu.Unlock()
		return entry.root, func() { c.release(dir) }, nil
	}
	cache := len(c.entries) < maxCachedDirectoryRoots
	if !cache {
		var oldestKey string
		var oldest *cachedDirectoryRoot
		for key, entry := range c.entries {
			if entry.refs == 0 && (oldest == nil || entry.used < oldest.used) {
				oldestKey, oldest = key, entry
			}
		}
		if oldest != nil {
			delete(c.entries, oldestKey)
			_ = oldest.root.Close()
			cache = true
		}
	}
	root, err := c.anchor.OpenRoot(dir)
	if err != nil {
		c.mu.Unlock()
		return nil, nil, err
	}
	if !cache {
		c.mu.Unlock()
		return root, func() { _ = root.Close() }, nil
	}
	c.entries[dir] = &cachedDirectoryRoot{root: root, refs: 1, used: c.clock}
	c.mu.Unlock()
	return root, func() { c.release(dir) }, nil
}

func (c *directoryRootCache) release(dir string) {
	c.mu.Lock()
	c.entries[dir].refs--
	c.mu.Unlock()
}

func (c *directoryRootCache) Close() {
	close(c.closeQueue)
	<-c.closerDone
	c.mu.Lock()
	defer c.mu.Unlock()
	for key, entry := range c.entries {
		_ = entry.root.Close()
		delete(c.entries, key)
	}
	_ = c.anchor.Close()
}
