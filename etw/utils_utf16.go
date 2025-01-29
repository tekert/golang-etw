//go:build windows
// +build windows

package etw

import (
	"syscall"
	"unsafe"
)

// Cache only small property strings, those are the most repeated
const maxUtf16CachedLength = 32

func Wcslen(p *uint16) (len uint64) {
	end := unsafe.Pointer(p)
	for *(*uint16)(end) != 0 {
		end = unsafe.Pointer(uintptr(end) + unsafe.Sizeof(*p))
		len++
	}
	return
}

// Copies a null terminated UTF16 string from a pointer to a
// new allocated memory
func CopyUTF16Ptr(src *uint16) *uint16 {
	if src == nil {
		return nil
	}
	length := Wcslen(src)
	dst := make([]uint16, length+1)
	copy(dst, unsafe.Slice(src, length+1))
	return &dst[0]
}

// UTF16BytesToString transforms a bytes array of UTF16 encoded characters to
// a Go string
func UTF16BytesToString(utf16 []byte) string {
	return UTF16ToStringETW(*(*[]uint16)(unsafe.Pointer(&utf16)))
}

// Ported from from go syscall package
//
// utf16PtrToStringGO is like UTF16ToString, but takes *uint16
// as a parameter instead of []uint16.
func UTF16PtrToString(p *uint16) string {
	if p == nil {
		return ""
	}
	end := unsafe.Pointer(p)
	n := 0
	for *(*uint16)(end) != 0 {
		end = unsafe.Pointer(uintptr(end) + unsafe.Sizeof(*p))
		n++
	}

	return UTF16ToStringETW(unsafe.Slice(p, n))
}

func UTF16AtOffsetToString(pstruct uintptr, offset uintptr) string {
	ptr := (*uint16)(unsafe.Pointer(pstruct + offset))
	return UTF16PtrToString(ptr)
}

// CacheGetString attempts to get string from cache
//
//go:inline
func UTF16CacheGetString(data []uint16) (string, bool) {
	return globalUtf16Cache.get(data)
}

// CacheSetString stores string in cache
//
//go:inline
func UTF16CacheSetString(data []uint16, value string) {
	if len(data) >= maxUtf16CachedLength {
		return
	}
	globalUtf16Cache.set(data, value)
}

// Main package function used to convert UTF16 to WTF8 go strings
// #go:inline
func UTF16ToStringETW(utf16 []uint16) string {
	// Try cache first
	if s, ok := UTF16CacheGetString(utf16); ok {
		return s
	}

	// Convert and cache result
	//s := etwutf16.DecodeWtf8(utf16)
	s := syscall.UTF16ToString(utf16)
	UTF16CacheSetString(utf16, s)
	return s
}
