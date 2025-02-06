//go:build amd64

package utf16f

import "unsafe"

//go:noescape
func utf16ToStringSSE2(src *uint16, srcLen int, dst []byte) (written int)

//go:noescape
func utf16ToStringSSE2_v1(src *uint16, srcLen int, dst []byte) (written int)

//go:noescape
func utf16ToStringSSE2_v2(src *uint16, srcLen int, dst []byte) (written int)

func DecodeSIMD(s []uint16) string {
	// Pre-calculate max size
	maxLen := 0
	for i, v := range s {
		if v == 0 {
			s = s[0:i]
			break
		}
		switch {
		case v <= rune1Max:
			maxLen += 1
		case v <= rune2Max:
			maxLen += 2
		default:
			// r is a non-surrogate that decodes to 3 bytes,
			// or is an unpaired surrogate (also 3 bytes in WTF-8),
			// or is one half of a valid surrogate pair.
			// If it is half of a pair, we will add 3 for the second surrogate
			// (total of 6) and overestimate by 2 bytes for the pair,
			// since the resulting rune only requires 4 bytes.
			maxLen += 3
		}
	}

	if len(s) == 0 {
		return ""
	}

	// Single allocation for buffer
	buf := make([]byte, maxLen)
	written := utf16ToStringSSE2(&s[0], len(s), buf)

	// Zero-allocation string conversion
	return unsafe.String(&buf[0], written)
}

func DecodeSIMD_v1(s []uint16) string {
	// Pre-calculate max size
	maxLen := 0
	for i, v := range s {
		if v == 0 {
			s = s[0:i]
			break
		}
		switch {
		case v <= rune1Max:
			maxLen += 1
		case v <= rune2Max:
			maxLen += 2
		default:
			// r is a non-surrogate that decodes to 3 bytes,
			// or is an unpaired surrogate (also 3 bytes in WTF-8),
			// or is one half of a valid surrogate pair.
			// If it is half of a pair, we will add 3 for the second surrogate
			// (total of 6) and overestimate by 2 bytes for the pair,
			// since the resulting rune only requires 4 bytes.
			maxLen += 3
		}
	}

	if len(s) == 0 {
		return ""
	}

	// Single allocation for buffer
	buf := make([]byte, maxLen)
	written := utf16ToStringSSE2_v1(&s[0], len(s), buf)

	// Zero-allocation string conversion
	return unsafe.String(&buf[0], written)
}

func DecodeSIMD_v2(s []uint16) string {
	// Pre-calculate max size
	maxLen := 0
	for i, v := range s {
		if v == 0 {
			s = s[0:i]
			break
		}
		switch {
		case v <= rune1Max:
			maxLen += 1
		case v <= rune2Max:
			maxLen += 2
		default:
			// r is a non-surrogate that decodes to 3 bytes,
			// or is an unpaired surrogate (also 3 bytes in WTF-8),
			// or is one half of a valid surrogate pair.
			// If it is half of a pair, we will add 3 for the second surrogate
			// (total of 6) and overestimate by 2 bytes for the pair,
			// since the resulting rune only requires 4 bytes.
			maxLen += 3
		}
	}

	if len(s) == 0 {
		return ""
	}

	// Single allocation for buffer
	buf := make([]byte, maxLen)
	written := utf16ToStringSSE2_v2(&s[0], len(s), buf)

	// Zero-allocation string conversion
	return unsafe.String(&buf[0], written)
}
