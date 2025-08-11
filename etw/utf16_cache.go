package etw

import (
	"sync"
)

// globalUtf16Cache is a cache for UTF-16 string conversions.
// It uses sync.Map, which is optimized for concurrent read-mostly scenarios,
// making it ideal for caching repeated strings like event property names.
var globalUtf16Cache = utf16Cache{}

// utf16Cache wraps a sync.Map for type safety and to provide the cache API.
type utf16Cache struct {
	data sync.Map
}

// hash calculates the FNV-1a hash for a UTF-16 slice.
//
//go:inline
func (c *utf16Cache) hash(data []uint16) uint64 {
	h := uint64(14695981039346656037) // FNV offset basis
	for _, v := range data {
		h ^= uint64(v)
		h *= 1099511628211 // Mult FNV prime
	}
	return h
}

// getKey retrieves a value from the cache. This uses sync.Map's highly
// optimized, often lock-free, read path.
func (c *utf16Cache) getKey(hash uint64) (string, bool) {
	// The Load method is the fast-path read for sync.Map.
	value, ok := c.data.Load(hash)
	if !ok {
		return "", false
	}
	// The value must be type-asserted back to a string.
	return value.(string), true
}

// setKey adds a value to the cache.
func (c *utf16Cache) setKey(hash uint64, value string) {
	// The Store method handles the concurrent-safe write.
	c.data.Store(hash, value)
}
