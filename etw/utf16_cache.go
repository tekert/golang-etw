package etw

import (
	"sync"
	"time"
)

var globalUtf16Cache = newUtf16Cache()

type utf16Cache struct {
	mu           sync.RWMutex
	data         map[uint64]string
	done         chan struct{}
	cleanupTimer time.Duration
}

func newUtf16Cache() *utf16Cache {
	c := &utf16Cache{
		data:         make(map[uint64]string, 1024), // Pre-allocate for common case
		done:         make(chan struct{}),
		cleanupTimer: 10 * time.Second, // clean up the cache every 10 seconds.
	}

	// Start map cleanup goroutine
	go c.cleanup()

	return c
}

// Simple and fast fnv1a hash function for UTF-16 data
//
//go:inline
func (c *utf16Cache) hash(data []uint16) uint64 {
	h := uint64(14695981039346656037) // FNV offset basis
	for _, v := range data {
		h ^= uint64(v) // h XOR value
		h *= 1099511628211 // Mult FNV prime
	}
	return h
}

//go:inline
func (c *utf16Cache) get(data []uint16) (string, bool) {
	c.mu.RLock()
	v, ok := c.data[c.hash(data)]
	c.mu.RUnlock()

	return v, ok
}

//go:inline
func (c *utf16Cache) set(data []uint16, value string) {
	c.mu.Lock()
	c.data[c.hash(data)] = value
	c.mu.Unlock()
}

// Periodically clear the entire cache
func (c *utf16Cache) cleanup() {
	ticker := time.NewTicker(c.cleanupTimer)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			c.mu.Lock()
			clear(c.data)
			c.mu.Unlock()

		case <-c.done:
			return
		}
	}
}

// Stop the cleanup goroutine
func (c *utf16Cache) stop() {
	close(c.done)
}
