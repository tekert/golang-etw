package etw

import (
	"sync"
)

// globalUtf16Cache is a cache for UTF-16 string conversions.
// It uses sync.Map, which is optimized for concurrent read-mostly scenarios,
// making it ideal for caching repeated strings like event property names.
var globalUtf16Cache = utf16Cache{}

const (
	// FNV-1a hash constants for 64-bit hash computation
	// These are the standard FNV-1a constants as defined in the FNV specification
	fnvOffset64 = 14695981039346656037 // FNV-1a 64-bit offset basis
	fnvPrime64  = 1099511628211        // FNV-1a 64-bit prime multiplier
)

// utf16Cache wraps a sync.Map for type safety and to provide the cache API.
type utf16Cache struct {
	data sync.Map // map[uint64]string - maps FNV-1a hash to converted string
}

// hash calculates the FNV-1a hash for a UTF-16 slice.
//
//go:inline
func (c *utf16Cache) hash(data []uint16) uint64 {
	h := uint64(fnvOffset64) // FNV-1a offset basis
	for _, v := range data {
		h ^= uint64(v)    // XOR with the 16-bit value
		h *= fnvPrime64   // Multiply by FNV prime
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
	// Type assertion is safe since we only store strings in this cache
	return value.(string), true
}

// setKey adds a value to the cache.
func (c *utf16Cache) setKey(hash uint64, value string) {
	// The Store method handles the concurrent-safe write.
	c.data.Store(hash, value)
}
