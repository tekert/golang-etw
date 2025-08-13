//go:build windows

package etw

import (
	"unsafe"

	"github.com/tekert/golang-etw/internal/utf16f"
)

const maxUtf16CachedLength2 = 256 // Don't cache strings larger than this.

// utf16Convert performs a cache lookup for a given string slice and its hash.
// On a cache miss, it calls the final utf16 conversion function and stores the result in the cache.
// This helper centralizes the core caching logic for all cacheable strings.
//
//go:inline
func utf16Convert(s []uint16, h uint64, n int) string {
	// For long strings, convert directly without caching to avoid polluting the cache.
	if n >= maxUtf16CachedLength2 {
		return utf16f.DecodeWtf8(s)
	}
	// If the hash wasn't pre-computed (e.g., from a slice), calculate it now.
	if h == 0 {
		// The probability is astronomically low (1 in 2^64) that a already hashed string was 0
		h = globalUtf16Cache.hash(s)
	}

	if str, ok := globalUtf16Cache.getKey(h); ok {
		return str // Cache hit!
	}
	// On cache miss, perform the conversion and store the result.
	// This is the single, centralized place where conversion happens for cached strings.
	str := utf16f.DecodeWtf8(s)
	globalUtf16Cache.setKey(h, str)
	return str
}

// UTF16PtrToString2 is the most performant way to convert a null-terminated
// UTF-16 pointer to a Go string. It finds the string length and calculates
// its hash in a single pass to optimize cache lookups.
func UTF16PtrToString(p *uint16) string {
	if p == nil {
		return ""
	}

	// Find the string length and calculate its hash in a single loop.
	// This specialized loop is the key to this function's performance.
	h := uint64(14695981039346656037) // FNV offset basis
	end := unsafe.Pointer(p)
	n := 0
	for {
		char := *(*uint16)(end)
		if char == 0 {
			break // Null terminator found
		}
		h ^= uint64(char)
		h *= 1099511628211 // FNV prime

		end = unsafe.Pointer(uintptr(end) + 2) // 2 bytes per uint16
		n++
	}

	if n == 0 {
		return ""
	}
	s := unsafe.Slice(p, n)

	return utf16Convert(s, h, n)
}

// UTF16SliceToString converts a UTF-16 slice to a string, using a cache for performance.
// For best performance, use UTF16PtrToString2 when you have a pointer.
func UTF16SliceToString(s []uint16) string {
	if len(s) == 0 {
		return ""
	}
	// Pass h=0 to signal that the hash needs to be computed inside the helper.
	return utf16Convert(s, 0, len(s))
}

// UTF16AtOffsetToString2 converts a UTF-16 string at a given offset from a pointer.
func UTF16AtOffsetToString(pstruct uintptr, offset uintptr) string {
	ptr := (*uint16)(unsafe.Pointer(pstruct + offset))
	return UTF16PtrToString(ptr)
}

// UTF16BytesToString2 transforms a byte slice of UTF16 encoded characters to a Go string.
func UTF16BytesToString(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	// This re-slice is safe because we calculate the correct length in uint16 chars.
	s := unsafe.Slice((*uint16)(unsafe.Pointer(unsafe.SliceData(b))), len(b)/2)
	return UTF16SliceToString(s)
}

// Wcslen finds the length of a null-terminated UTF-16 string in characters.
func Wcslen(p *uint16) (length int) {
	if p == nil {
		return 0
	}
	end := unsafe.Pointer(p)
	for *(*uint16)(end) != 0 {
		end = unsafe.Pointer(uintptr(end) + 2) // 2 bytes per uint16
		length++
	}
	return
}

// CopyUTF16Ptr Copies a null terminated UTF16 string from a pointer to a
// new allocated memory
func CopyUTF16Ptr(src *uint16) *uint16 {
	if src == nil {
		return nil
	}
	length := Wcslen(src)
	if length == 0 {
		// Return a pointer to a null terminator, consistent with some Windows API behavior.
		return &[]uint16{0}[0]
	}
	dst := make([]uint16, length+1) // +1 for null terminator
	copy(dst, unsafe.Slice(src, length+1))
	return &dst[0]
}
