//go:build windows

package etw

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"path/filepath"
	"runtime"
	"strconv"
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

const hextableu = "0123456789ABCDEF"
const hextable = "0123456789abcdef"

// Ported from the hex package to print uppercase hex efficiently
//
// Encode encodes src into [EncodedLen](len(src))
// bytes of dst. As a convenience, it returns the number
// of bytes written to dst, but this value is always [EncodedLen](len(src)).
// Encode implements hexadecimal encoding.
func HexEncodeU(dst, src []byte) int {
	j := 0
	for _, v := range src {
		dst[j] = hextableu[v>>4]
		dst[j+1] = hextableu[v&0x0f]
		j += 2
	}
	return len(src) * 2
}

// Ported from the hex package to print lowercase hex just for convenience.
//
// Encode encodes src into [EncodedLen](len(src))
// bytes of dst. As a convenience, it returns the number
// of bytes written to dst, but this value is always [EncodedLen](len(src)).
// Encode implements hexadecimal encoding.
func HexEncode(dst, src []byte) int {
	j := 0
	for _, v := range src {
		dst[j] = hextable[v>>4]
		dst[j+1] = hextable[v&0x0f]
		j += 2
	}
	return len(src) * 2
}

// Ported from the hex package to print UPPERCASE hex just for convenience.
//
// EncodeToString returns the hexadecimal encoding of src.
func HexEncodeToStringU(src []byte) string {
	dst := make([]byte, len(src)*2) // 1 byte = 2 hex chars
	HexEncodeU(dst, src)
	return unsafe.String(unsafe.SliceData(dst), len(dst))
}

// EncodeToString returns the hexadecimal encoding of src. with prefix 0x
// Way more efficient than 2 allocations
func HexEncodeToStringUPrefix(src []byte) string {
	dst := make([]byte, 2+len(src)*2) // 1 byte = 2 hex chars
	dst[0] = '0'
	dst[1] = 'x'
	HexEncodeU(dst[2:], src)
	return unsafe.String(unsafe.SliceData(dst), len(dst))
}

// Checking len() is costly, so no optional parameters with ... slice
// have to repeat functions.. go...

// Unsigned integer helpers - uppercase

func HexUint64U(n uint64) string {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, n)
	return HexEncodeToStringU(b)
}
func HexUint64UPrefix(n uint64) string {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, n)
	return HexEncodeToStringUPrefix(b)
}

func HexUint32U(n uint32) string {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, n)
	return HexEncodeToStringU(b)
}
func HexUint32UPrefix(n uint32) string {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, n)
	return HexEncodeToStringUPrefix(b)
}

func HexUint16U(n uint16) string {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, n)
	return HexEncodeToStringU(b)
}
func HexUint16UPrefix(n uint16) string {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, n)
	return HexEncodeToStringUPrefix(b)
}

func HexUint8U(n uint8) string {
	return HexEncodeToStringU([]byte{n})
}
func HexUint8UPrefix(n uint8) string {
	return HexEncodeToStringUPrefix([]byte{n})
}

// Signed integer helpers - uppercase

func HexInt64U(n int64) string {
	return HexUint64U(uint64(n))
}
func HexInt64UPrefix(n int64) string {
	return HexUint64UPrefix(uint64(n))
}

func HexInt32U(n int32) string {
	return HexUint32U(uint32(n))
}
func HexInt32UPrefix(n int32) string {
	return HexUint32UPrefix(uint32(n))
}

func HexInt16U(n int16) string {
	return HexUint16U(uint16(n))
}
func HexInt16UPrefix(n int16) string {
	return HexUint16UPrefix(uint16(n))
}

func HexInt8U(n int8) string {
	return HexUint8U(uint8(n))
}
func HexInt8UPrefix(n int8) string {
	return HexUint8UPrefix(uint8(n))
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

func getGoroutineID() int64 {
	var buf [64]byte
	n := runtime.Stack(buf[:], false)
	id := strings.Fields(strings.TrimPrefix(string(buf[:n]), "goroutine "))[0]
	val, _ := strconv.ParseInt(id, 10, 64)
	return val
}

func stackUsage() {
	buf := make([]byte, 64)
	for {
		n := runtime.Stack(buf, false)
		// If trace fits in buffer
		if n < len(buf) {
			fmt.Printf("stack: %d bytes", n)
			return
		}
		buf = make([]byte, 2*len(buf))
	}
}
