//go:build windows
// +build windows

package etw

import (
	"crypto/rand"
	"fmt"
	"log/slog"
	"syscall"
	"unsafe"
)

func max(a, b int) int {
	if a < b {
		return b
	}
	return a
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

func CopyData(pointer uintptr, size int) []byte {
	out := make([]byte, 0, size)
	for it := pointer; it != pointer+uintptr(size); it++ {
		b := (*byte)(unsafe.Pointer(it))
		out = append(out, *b)
	}
	return out
}

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

// https://pkg.go.dev/log/slog@go1.23.4#hdr-Performance_considerations
type lazyDecodeSource struct {
	ds DecodingSource
}

func (l lazyDecodeSource) LogValue() slog.Value {
	// Called only if log is enabled
	return slog.StringValue(aSource[l.ds])
}
