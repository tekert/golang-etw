//go:build windows
// +build windows

package etw

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

const (
	nullGUIDStr = "{00000000-0000-0000-0000-000000000000}"
)

var (
	nullGUID = GUID{}
)

/*
typedef struct _GUID {
	DWORD Data1;
	WORD Data2;
	WORD Data3;
	BYTE Data4[8];
} GUID;
*/

// GUID structure
// Example: {9E814AAD-3204-11D2-9A82-006008A86939} =
// GUID(0x9e814aad, 0x3204, 0x11d2, [8]byte{0x9a, 0x82, 0x00, 0x60, 0x08, 0xa8, 0x69, 0x39})
type GUID struct {
	Data1 uint32
	Data2 uint16
	Data3 uint16
	Data4 [8]byte
}

// IsZero checks if GUID is all zeros
func (g *GUID) IsZero() bool {
	return g.Equals(&nullGUID)
}

// UPPERCASE String representation of the GUID
// These are 10x more performant than sprintf
func (g *GUID) String() string {
	var b [38]byte
	b[0] = '{'
	b[37] = '}'

	// Avoid slice allocations
	var d1 [4]byte
	d1[0] = byte(g.Data1 >> 24)
	d1[1] = byte(g.Data1 >> 16)
	d1[2] = byte(g.Data1 >> 8)
	d1[3] = byte(g.Data1)

	var d2 [2]byte
	d2[0] = byte(g.Data2 >> 8)
	d2[1] = byte(g.Data2)

	var d3 [2]byte
	d3[0] = byte(g.Data3 >> 8)
	d3[1] = byte(g.Data3)

    HexEncodeU(b[1:9], d1[:])
    b[9] = '-'
    HexEncodeU(b[10:14], d2[:])
    b[14] = '-'
    HexEncodeU(b[15:19], d3[:])
    b[19] = '-'
    HexEncodeU(b[20:24], g.Data4[:2])
    b[24] = '-'
    HexEncodeU(b[25:37], g.Data4[2:])

	return string(b[:])
}

// lowercase string representation of the GUID
// These are 10x more performant than sprintf
func (g *GUID) StringL() string {
	var b [38]byte
	b[0] = '{'
	b[37] = '}'

	// Avoid slice allocations
	var d1 [4]byte
	d1[0] = byte(g.Data1 >> 24)
	d1[1] = byte(g.Data1 >> 16)
	d1[2] = byte(g.Data1 >> 8)
	d1[3] = byte(g.Data1)

	var d2 [2]byte
	d2[0] = byte(g.Data2 >> 8)
	d2[1] = byte(g.Data2)

	var d3 [2]byte
	d3[0] = byte(g.Data3 >> 8)
	d3[1] = byte(g.Data3)

    HexEncode(b[1:9], d1[:])
    b[9] = '-'
    HexEncode(b[10:14], d2[:])
    b[14] = '-'
    HexEncode(b[15:19], d3[:])
    b[19] = '-'
    HexEncode(b[20:24], g.Data4[:2])
    b[24] = '-'
    HexEncode(b[25:37], g.Data4[2:])

	return string(b[:])
}

func (g *GUID) Equals(other *GUID) bool {
	return g.Data1 == other.Data1 &&
		g.Data2 == other.Data2 &&
		g.Data3 == other.Data3 &&
		g.Data4[0] == other.Data4[0] &&
		g.Data4[1] == other.Data4[1] &&
		g.Data4[2] == other.Data4[2] &&
		g.Data4[3] == other.Data4[3] &&
		g.Data4[4] == other.Data4[4] &&
		g.Data4[5] == other.Data4[5] &&
		g.Data4[6] == other.Data4[6] &&
		g.Data4[7] == other.Data4[7]
}

var (
	guidRE = regexp.MustCompile(`^\{?[A-F0-9]{8}-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{12}\}?$`)
)

// MustParseGUID parses a guid string into a GUID struct or panics
func MustParseGUID(sguid string) (guid *GUID) {
	var err error
	if guid, err = ParseGUID(sguid); err != nil {
		panic(err)
	}
	return
}

// ParseGUID parses a guid string into a GUID structure
func ParseGUID(guid string) (g *GUID, err error) {
	var u uint64

	g = &GUID{}
	guid = strings.ToUpper(guid)
	if !guidRE.MatchString(guid) {
		return nil, fmt.Errorf("bad GUID format")
	}
	guid = strings.Trim(guid, "{}")
	sp := strings.Split(guid, "-")

	if u, err = strconv.ParseUint(sp[0], 16, 32); err != nil {
		return
	}
	g.Data1 = uint32(u)
	if u, err = strconv.ParseUint(sp[1], 16, 16); err != nil {
		return
	}
	g.Data2 = uint16(u)
	if u, err = strconv.ParseUint(sp[2], 16, 16); err != nil {
		return
	}
	g.Data3 = uint16(u)
	if u, err = strconv.ParseUint(sp[3], 16, 16); err != nil {
		return
	}
	g.Data4[0] = uint8(u >> 8)
	g.Data4[1] = uint8(u & 0xff)
	if u, err = strconv.ParseUint(sp[4], 16, 64); err != nil {
		return
	}
	g.Data4[2] = uint8((u >> 40))
	g.Data4[3] = uint8((u >> 32) & 0xff)
	g.Data4[4] = uint8((u >> 24) & 0xff)
	g.Data4[5] = uint8((u >> 16) & 0xff)
	g.Data4[6] = uint8((u >> 8) & 0xff)
	g.Data4[7] = uint8(u & 0xff)

	return
}
