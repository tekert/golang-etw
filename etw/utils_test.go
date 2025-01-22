//go:build windows
// +build windows

package etw

import (
	"syscall"
	"testing"
	"unsafe"

	"github.com/0xrawsec/toast"
)

func TestUtils(t *testing.T) {

	tt := toast.FromT(t)

	s := "this is a utf16 string"
	sutf16, err := syscall.UTF16PtrFromString(s)
	tt.CheckErr(err)

	tt.Assert(UTF16PtrToString(sutf16) == s)
	tt.Assert(Wcslen(sutf16) == uint64(len(s)))

	// we have to double the length because we are in utf16
	butf16 := CopyData(unsafe.Pointer(sutf16), len(s)*2)

	tt.Assert(len(butf16) == len(s)*2)
	tt.Assert(UTF16BytesToString(butf16) == s)

	uuid, err := UUID()
	tt.CheckErr(err)
	t.Log(uuid)
}

// Helper
// Allocate SID with proper SubAuthority array size
func AllocSID(t testing.TB, subAuthorityCount uint8) *SID {
	// Calculate total size needed
	sidSize := unsafe.Sizeof(SID{}) - unsafe.Sizeof([1]uint32{}) +
		uintptr(subAuthorityCount)*unsafe.Sizeof(uint32(0))

	// Allocate contiguous memory
	memory := make([]byte, sidSize)

	// Get SID pointer
	sid := (*SID)(unsafe.Pointer(&memory[0]))

	// Initialize fields
	sid.Revision = 1
	sid.SubAuthorityCount = subAuthorityCount

	return sid
}

func TestSIDConversion(t *testing.T) {
	tt := toast.FromT(t)

	tests := []struct {
		name     string
		subAuths []uint32 // SubAuthorities to set
		auth     [6]byte  // IdentifierAuthority value
		want     string   // Expected SID string
	}{
		{
			name:     "System SID",
			subAuths: []uint32{18},
			auth:     [6]byte{0, 0, 0, 0, 0, 5}, // NT Authority
			want:     "S-1-5-18",
		},
		{
			name:     "Local Admin SID",
			subAuths: []uint32{32, 544},
			auth:     [6]byte{0, 0, 0, 0, 0, 5}, // NT Authority
			want:     "S-1-5-32-544",
		},
		{
			name: "Domain User SID",
			subAuths: []uint32{
				21,         // SECURITY_NT_NON_UNIQUE
				1068291655, // Domain ID part 1
				1087365685, // Domain ID part 2
				3231394758, // Domain ID part 3
				1001,       // User RID
			},
			auth: [6]byte{0, 0, 0, 0, 0, 5}, // NT Authority
			want: "S-1-5-21-1068291655-1087365685-3231394758-1001",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Create SID with proper memory layout
			sid := AllocSID(t, uint8(len(tc.subAuths)))
			tt.Assert(sid != nil, "AllocSID failed")

			sid.Revision = 1
			sid.IdentifierAuthority.Value = tc.auth

			// Set SubAuthorities
			subAuth := sid.SubAuthorities()
			copy(subAuth, tc.subAuths)

			// Test Windows API
			gotAPI, err := ConvertSidToStringSidW(sid)
			tt.CheckErr(err)

			// Test GO implementation
			gotGO, err := ConvertSidToStringSidGO(sid)
			tt.CheckErr(err)

			// Compare results
			tt.Assert(gotAPI == tc.want,
				"API result mismatch: got %v, want %v", gotAPI, tc.want)
			tt.Assert(gotGO == tc.want,
				"GO result mismatch: got %v, want %v", gotGO, tc.want)
			tt.Assert(gotAPI == gotGO,
				"Results differ: API=%v, GO=%v", gotAPI, gotGO)
		})
	}
}

// From the custom parser
func TestSwapFunctions(t *testing.T) {
	tt := toast.FromT(t)

	// Test SwapBytes
	t.Run("SwapBytes", func(t *testing.T) {

		// Even length
		even := []byte{0x12, 0x34, 0x56, 0x78}
		SwapBytes(even)
		tt.Assert(even[0] == 0x78 && even[1] == 0x56 &&
			even[2] == 0x34 && even[3] == 0x12)

		// Odd length
		odd := []byte{0x12, 0x34, 0x56}
		SwapBytes(odd)
		tt.Assert(odd[0] == 0x56 && odd[1] == 0x34 && odd[2] == 0x12)

		// Single byte (should not change)
		single := []byte{0x12}
		SwapBytes(single)
		tt.Assert(single[0] == 0x12)

		// Empty slice (should not panic)
		empty := []byte{}
		SwapBytes(empty)
	})

	// Test Swap16
	t.Run("Swap16", func(t *testing.T) {
		tt := toast.FromT(t)

		// Test values
		tt.Assert(Swap16(0x1234) == 0x3412)
		tt.Assert(Swap16(0xFF00) == 0x00FF)
		tt.Assert(Swap16(0x0000) == 0x0000)
		tt.Assert(Swap16(0xFFFF) == 0xFFFF)

		// Test idempotency
		n := uint16(0x1234)
		tt.Assert(Swap16(Swap16(n)) == n)
	})

	// Test Swap32
	t.Run("Swap32", func(t *testing.T) {
		tt := toast.FromT(t)

		// Test values
		tt.Assert(Swap32(0x12345678) == 0x78563412)
		tt.Assert(Swap32(0xFF000000) == 0x000000FF)
		tt.Assert(Swap32(0x00000000) == 0x00000000)
		tt.Assert(Swap32(0xFFFFFFFF) == 0xFFFFFFFF)

		// Test idempotency
		n := uint32(0x12345678)
		tt.Assert(Swap32(Swap32(n)) == n)
	})

	// Test Swap64
	t.Run("Swap64", func(t *testing.T) {
		tt := toast.FromT(t)

		// Test values
		tt.Assert(Swap64(0x1234567890ABCDEF) == 0xEFCDAB9078563412)
		tt.Assert(Swap64(0xFF00000000000000) == 0x00000000000000FF)
		tt.Assert(Swap64(0x0000000000000000) == 0x0000000000000000)
		tt.Assert(Swap64(0xFFFFFFFFFFFFFFFF) == 0xFFFFFFFFFFFFFFFF)

		// Test idempotency
		n := uint64(0x1234567890ABCDEF)
		tt.Assert(Swap64(Swap64(n)) == n)
	})
}
