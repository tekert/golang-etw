package etw

import (
	"sync"
)

var globalUtf16Cache = newUtf16Cache()

type utf16Cache struct {
	mu         sync.RWMutex
	data       map[uint64]string
	maxEntries int
}

func newUtf16Cache() *utf16Cache {
	c := &utf16Cache{
		data:       make(map[uint64]string, 1024), // Pre-allocate for common case
		maxEntries: 1024,                          // Default max entries
	}

	return c
}

// Simple and fast fnv1a hash function for UTF-16 data
//
//go:inline
func (c *utf16Cache) hash(data []uint16) uint64 {
	h := uint64(14695981039346656037) // FNV offset basis
	for _, v := range data {
		h ^= uint64(v)     // h XOR value
		h *= 1099511628211 // Mult FNV prime
	}
	return h
}

//go:inline
func (c *utf16Cache) getData(data []uint16) (string, bool) {
	c.mu.RLock()
	v, ok := c.data[c.hash(data)]
	c.mu.RUnlock()

	return v, ok
}

func (c *utf16Cache) getKey(hash uint64) (string, bool) {
	c.mu.RLock()
	v, ok := c.data[hash]
	c.mu.RUnlock()

	return v, ok
}

func (c *utf16Cache) setKey(hash uint64, value string) {
	c.mu.Lock()
	if len(c.data) >= c.maxEntries {
		clear(c.data)
	}
	c.data[hash] = value
	c.mu.Unlock()
}

//go:inline
func (c *utf16Cache) setData(data []uint16, value string) (hash uint64) {
	c.mu.Lock()
	if len(c.data) >= c.maxEntries {
		clear(c.data)
	}
	hash = c.hash(data)
	c.data[hash] = value
	c.mu.Unlock()
	return
}
