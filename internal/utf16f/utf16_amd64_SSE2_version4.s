#include "textflag.h"

// Optional constants for SSE2-based checks and markers
#define maskAscii 0xFF80  // Mask to check if a UTF-16 code unit is ASCII (<= 0x7F). Bitwise AND.
#define maskSurr  0xF800  // Mask to check if a UTF-16 code unit is a surrogate. Bitwise AND.
#define surr1    0xD800  // Start of the high-surrogate range (0xD800 - 0xDBFF)
#define surr2    0xDC00  // Start of the low-surrogate range (0xDC00 - 0xDFFF)
#define surr3    0xE000  // Marks the end of the surrogate pair check range
#define surrSelf 0x10000 // Offset added to the combined surrogate pair to get the actual Unicode code point.
#define t2       0xC0    // First byte of a 2-byte UTF-8 sequence (110xxxxx)
#define t3       0xE0    // First byte of a 3-byte UTF-8 sequence (1110xxxx)
#define t4       0xF0    // First byte of a 4-byte UTF-8 sequence (11110xxx)
#define tx       0x80    // Subsequent bytes of a multi-byte UTF-8 sequence (10xxxxxx)
#define maskx    0x3F    // Mask to extract the last 6 bits of a code unit for UTF-8 encoding (00111111)

// utf16ToStringSSE2_v4 implements an SSE2-accelerated UTF-16 to WTF-8 conversion.
TEXT ·utf16ToStringSSE2_v4(SB), NOSPLIT, $0-48
    // Go function signature:
    // func utf16ToStringSSE2_v4(src *uint16, srcLen int, dst []byte) (written int)
    // Arguments (Plan 9 ASM, AMD64):
    //   src    at +0(FP)   -> RSI
    //   srcLen at +8(FP)   -> R9
    //   dst    at +16(FP)  -> RDI (plus len/cap)
    //   return at +40(FP)

    MOVQ src+0(FP), SI       // Source pointer
    MOVQ srcLen+8(FP), R9    // Source length (UTF-16 code units)
    MOVQ dst+16(FP), DI      // Destination pointer
    MOVQ DI, R10             // Original dst (for calculating bytes written)

    // If fewer than 8 UTF-16 chars, skip straight to scalar code
    CMPQ R9, $8
    JL scalar_loop

    // Prepare SSE2 masks for ASCII/surrogate checks
    PCMPEQW X6, X6
    PSLLW $7, X6             // X6 => 0xFF80, for ASCII check
    PCMPEQW X7, X7
    PSRLW $5, X7             // X7 => 0xF800, for surrogate check

sse_main:
    // Can we process 8 UTF-16 chars at once?
    CMPQ R9, $8
    JL scalar_loop

    // Load 8 UTF-16 code units into X0
    MOVOU (SI), X0

    // Check if all are < 0x80
    MOVOA X0, X1
    PAND X6, X1          // mask with 0xFF80
    PXOR X2, X2
    PCMPEQW X1, X2
    PMOVMSKB X2, AX
    CMPL AX, $0xFFFF
    JNE check_surrogates // if not all zero => fallback

    // All ASCII => pack to 8 bytes
    PACKUSWB X0, X0
    MOVQ X0, (DI)
    ADDQ $16, SI         // consumed 8 UTF-16 chars => 16 bytes
    ADDQ $8, DI          // wrote 8 ASCII bytes
    SUBQ $8, R9
    JMP sse_main

check_surrogates:
    // If there's any char >= 0x80 or a surrogate, go scalar
    JMP scalar_loop

// Scalar fallback for everything else (BMP, surrogates, leftovers)
scalar_loop:
    TESTQ R9, R9
    JE done

    // Load next UTF-16 word zero-extended into AX
    MOVWLZX (SI), AX
    ADDQ $2, SI
    DECQ R9

    CMPQ AX, $0x800
    JAE encode_3byte_inline // >= 0x800

    CMPQ AX, $0x80
    JB encode_ascii // < 0x80

    // 2-byte
    MOVQ AX, CX
    SHRQ $6, CX
    ORB $t2, CL
    MOVB CL, (DI)
    MOVQ AX, CX
    ANDB $maskx, CL
    ORB $tx, CL
    MOVB CL, 1(DI)
    ADDQ $2, DI
    JMP scalar_loop

encode_ascii:
    MOVB AL, (DI)
    INCQ DI
    JMP scalar_loop

encode_3byte_inline:
    CMPQ AX, $surr1
    JB encode_3byte

    CMPQ AX, $surr3
    JAE encode_3byte

    // It's in [0xD800..0xDFFF], check if it's a high or invalid surrogate
    CMPQ AX, $surr2
    JAE encode_surrogate_wtf8
    CMPQ R9, $1
    JL encode_surrogate_wtf8

    // Load the next word for the low surrogate
    MOVWLZX (SI), BX
    CMPQ BX, $surr2
    JB encode_surrogate_wtf8
    CMPQ BX, $surr3
    JAE encode_surrogate_wtf8

    // Valid surrogate pair
    SUBQ $surr1, AX
    SHLQ $10, AX
    SUBQ $surr2, BX
    ADDQ BX, AX
    ADDQ $surrSelf, AX

    // Encode as 4-byte WTF-8
    MOVB $t4, (DI)
    MOVQ AX, CX
    SHRQ $18, CX
    ORB CL, (DI)
    MOVQ AX, CX
    SHRQ $12, CX
    ANDB $maskx, CL
    ORB $tx, CL
    MOVB CL, 1(DI)
    MOVQ AX, CX
    SHRQ $6, CX
    ANDB $maskx, CL
    ORB $tx, CL
    MOVB CL, 2(DI)
    MOVQ AX, CX
    ANDB $maskx, CL
    ORB $tx, CL
    MOVB CL, 3(DI)

    ADDQ $4, DI
    ADDQ $2, SI    // skip second surrogate
    DECQ R9
    JMP scalar_loop

encode_surrogate_wtf8:
    // Encode a standalone surrogate in WTF-8 (3-byte form ED A0.. etc.)
    // AX holds the original surrogate code unit
    MOVQ AX, CX
    SUBQ $surr1, CX
    SHRQ $6, CX
    ORB $0xA0, CL
    MOVB $0xED, (DI)
    MOVB CL, 1(DI)
    MOVQ AX, CX
    ANDB $0x3F, CL
    ORB $0x80, CL
    MOVB CL, 2(DI)
    ADDQ $3, DI
    JMP scalar_loop

encode_3byte:
    // 3-byte
    MOVQ AX, CX
    SHRQ $12, CX
    ORB $t3, CL
    MOVB CL, (DI)
    MOVQ AX, CX
    SHRQ $6, CX
    ANDB $maskx, CL
    ORB $tx, CL
    MOVB CL, 1(DI)
    MOVQ AX, CX
    ANDB $maskx, CL
    ORB $tx, CL
    MOVB CL, 2(DI)
    ADDQ $3, DI
    JMP scalar_loop

done:
    // Calculate total bytes written
    SUBQ R10, DI
    MOVQ DI, ret+40(FP)
    RET
