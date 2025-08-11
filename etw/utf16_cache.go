package etw

import (
	"sync"
)

const (
	// Using a power of 2 for shardCount allows for faster modulo using bitwise AND.
	utf16CacheShardCount = 256
)

// globalUtf16Cache is a sharded cache to reduce lock contention.
var globalUtf16Cache = newUtf16Cache()

// utf16CacheShard holds a single, lockable shard of the cache.
type utf16CacheShard struct {
	mu   sync.RWMutex
	data map[uint64]string
}

// utf16Cache is the main sharded cache structure. It contains multiple shards
// to allow for concurrent access with minimal contention.
type utf16Cache struct {
	shards [utf16CacheShardCount]*utf16CacheShard
	// maxEntriesPerShard can be tuned based on the expected number of unique strings.
	maxEntriesPerShard int
}

// newUtf16Cache creates and initializes a new sharded cache.
func newUtf16Cache() *utf16Cache {
	c := &utf16Cache{}
	c.maxEntriesPerShard = 64 // default max entries per shard
	for i := range utf16CacheShardCount {
		c.shards[i] = &utf16CacheShard{
			data: make(map[uint64]string, c.maxEntriesPerShard), // Pre-allocate for common case
		}
	}
	return c
}

// getShard returns the appropriate shard for a given hash using a fast bitwise AND.
//
//go:inline
func (c *utf16Cache) getShard(hash uint64) *utf16CacheShard {
	return c.shards[hash&(utf16CacheShardCount-1)]
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

// getKey retrieves a value from the cache for a given hash. It locks only one shard.
func (c *utf16Cache) getKey(hash uint64) (string, bool) {
	shard := c.getShard(hash)
	shard.mu.RLock()
	s, ok := shard.data[hash]
	shard.mu.RUnlock()
	return s, ok
}

// setKey adds a value to the cache. It locks only one shard.
func (c *utf16Cache) setKey(hash uint64, value string) {
	shard := c.getShard(hash)
	shard.mu.Lock()
	// Simple eviction: if a shard is full, clear just that shard.
	if len(shard.data) >= c.maxEntriesPerShard {
		// This prevents unbounded memory growth in one shard.
		clear(shard.data)
	}
	shard.data[hash] = value
	shard.mu.Unlock()
}
