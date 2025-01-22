//go:build windows
// +build windows

package etw

import (
	"crypto/rand"
	"fmt"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

// noCopy may be added to structs which must not be copied
// after the first use.
//
// See https://golang.org/issues/8005#issuecomment-190753527
// for details.
//
// Note that it must not be embedded, due to the Lock and Unlock methods.
type noCopy struct{}

// Lock is a no-op used by -copylocks checker from `go vet`.
func (*noCopy) Lock()   {}
func (*noCopy) Unlock() {}

// Windows FILETIME constants
const (
	WINDOWS_TICK     = 100         // 100-nanosecond intervals
	EPOCH_DIFF       = 11644473600 // seconds between Windows epoch (1601) and Unix epoch (1970)
	TICKS_PER_SECOND = 10000000    // 1 second = 10,000,000 ticks
)

// Faster than syscall.Filetime.Nanoseconds() on edge cases.
// UTCTimeStamp converts a Windows FILETIME (100-nanosecond intervals since 1601)
// to a Unixtime.Time
func UnixTimeStamp(fileTime int64) time.Time {
	// Convert to Unix epoch
	unixTime := fileTime - (EPOCH_DIFF * TICKS_PER_SECOND)

	// Calculate seconds and remaining ticks
	seconds := unixTime / TICKS_PER_SECOND
	remaining := unixTime % TICKS_PER_SECOND

	// Convert remaining ticks to nanoseconds (multiply by 100)
	nanos := remaining * WINDOWS_TICK

	return time.Unix(seconds, nanos)
}

// UTCTimeStamp converts a Windows FILETIME (100-nanosecond intervals since 1601)
// to a Unix UTC time.Time
func UTCTimeStamp2(ft *syscall.Filetime) time.Time {
	return time.Unix(0, ft.Nanoseconds()).UTC()
}

func max(a, b int) int {
	if a < b {
		return b
	}
	return a
}

// These are faster than the go binary package.

// SwapBytes converts between little and big endian
func SwapBytes(b []byte) {
	for i := 0; i < len(b)/2; i++ {
		j := len(b) - i - 1
		b[i], b[j] = b[j], b[i]
	}
}

// Swap16 converts uint16 between little and big endian.
func Swap16(n uint16) uint16 {
	return (n << 8) | (n >> 8)
}

// swap32 converts uint32 between little and big endian
func Swap32(n uint32) uint32 {
	return (n << 24) | ((n << 8) & 0x00FF0000) |
		((n >> 8) & 0x0000FF00) | (n >> 24)
}

// swap64 converts uint64 between little and big endian
func Swap64(n uint64) uint64 {
	return (n << 56) | ((n << 40) & 0xFF000000000000) |
		((n << 24) & 0xFF0000000000) | ((n << 8) & 0xFF00000000) |
		((n >> 8) & 0xFF000000) | ((n >> 24) & 0xFF0000) |
		((n >> 40) & 0xFF00) | (n >> 56)
}

// UTF16BytesToString transforms a bytes array of UTF16 encoded characters to
// a Go string
func UTF16BytesToString(utf16 []byte) string {
	return syscall.UTF16ToString(*(*[]uint16)(unsafe.Pointer(&utf16)))
}

func Wcslen(uintf16 *uint16) (len uint64) {
	for it := uintptr((unsafe.Pointer(uintf16))); ; it += 2 {
		wc := (*uint16)(unsafe.Pointer(it))
		if *wc == 0 {
			return
		}
		len++
	}
}

// Ported from from go syscall packag
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

	return syscall.UTF16ToString(unsafe.Slice(p, n))
}

func UTF16AtOffsetToString(pstruct uintptr, offset uintptr) string {
	ptr := (*uint16)(unsafe.Pointer(pstruct + offset))
	return UTF16PtrToString(ptr)
}

// // UTF16PtrToString transforms a *uint16 to a Go string
// DEPRECATED the one ported from go syscall package is 48% faster than this
// wich uses UTF16AtOffsetToString_slow
// func UTF16PtrToString(utf16 *uint16) string {
// 	return UTF16AtOffsetToString_slow(uintptr(unsafe.Pointer(utf16)), 0)
// }

// too many allocations - DEPRECATED
// func UTF16AtOffsetToString_slow(pstruct uintptr, offset uintptr) string {
// 	out := make([]uint16, 0, 64)
// 	wc := (*uint16)(unsafe.Pointer(pstruct + offset))
// 	for i := uintptr(2); *wc != 0; i += 2 {
// 		out = append(out, *wc)
// 		wc = (*uint16)(unsafe.Pointer(pstruct + offset + i))
// 	}
// 	return syscall.UTF16ToString(out)
// }

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

func CopyData(pointer unsafe.Pointer, size int) []byte {
	if size <= 0 {
		return nil
	}
	// Create a slice from the pointer without copying memory
	src := unsafe.Slice((*byte)(pointer), size)
	dst := make([]byte, size)
	copy(dst, src)
	return dst
}

// inneficient - delete 3x slower than CopyData and a bit unsafe with uintptr.
// func CopyData_old(pointer uintptr, size int) []byte {
// 	out := make([]byte, 0, size)
// 	for it := pointer; it != pointer+uintptr(size); it++ {
// 		b := (*byte)(unsafe.Pointer(it))
// 		out = append(out, *b)
// 	}
// 	return out
// }

// UUID is a simple UUIDgenerator
func UUID() (uuid string, err error) {
	b := make([]byte, 16)
	_, err = rand.Read(b)
	if err != nil {
		return
	}
	uuid = fmt.Sprintf("%X-%X-%X-%X-%X", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
	return
}

// No cgo/syscalls needed
// replaces ConvertSidToStringSidW from Windows API
func ConvertSidToStringSidGO(sid *SID) (string, error) {
	// Basic validation
	if sid == nil {
		return "", nil
	}

	// Validate SID structure // SID_MAX_SUB_AUTHORITIES = 15
	if sid.Revision != 1 || sid.SubAuthorityCount > 15 {
		return "", fmt.Errorf("the SID is not valid")
	}

	// Convert identifier authority
	// High 2 bytes are used only if value > 2^32
	auth := uint64(sid.IdentifierAuthority.Value[5]) |
		uint64(sid.IdentifierAuthority.Value[4])<<8 |
		uint64(sid.IdentifierAuthority.Value[3])<<16 |
		uint64(sid.IdentifierAuthority.Value[2])<<24 |
		uint64(sid.IdentifierAuthority.Value[1])<<32 |
		uint64(sid.IdentifierAuthority.Value[0])<<40

	// Start with S-1
	result := fmt.Sprintf("S-%d-%d", sid.Revision, auth)

	// Add sub authorities
	subAuth := unsafe.Slice(&sid.SubAuthority[0], sid.SubAuthorityCount)
	for i := 0; i < int(sid.SubAuthorityCount); i++ {
		result += fmt.Sprintf("-%d", subAuth[i])
	}

	return result, nil
}

func isETLFile(path string) bool {
	// Convert to clean Windows path
	clean := filepath.Clean(path)
	if !strings.EqualFold(filepath.Ext(clean), ".etl") {
		return false
	}
	// Check if absolute path or UNC
	return filepath.IsAbs(clean) || strings.HasPrefix(clean, "\\\\")
}
