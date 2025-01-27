#include "textflag.h"

// UTF-8 Encoding Constants
#define tx 0x80    // 10xxxxxx continuation byte marker
#define t2 0xC0    // 110xxxxx 2-byte sequence marker
#define t3 0xE0    // 1110xxxx 3-byte sequence marker
#define t4 0xF0    // 11110xxx 4-byte sequence marker
#define maskx 0x3F // 00111111 mask for continuation bytes

// UTF-16 Surrogate Constants
#define surr1 0xd800  // High surrogate start
#define surr2 0xdc00  // Low surrogate start
#define surr3 0xe000  // Surrogate end
#define surrSelf 0x10000 // Surrogate pair offset

// Make constants accessible
GLOBL constants<>(SB), RODATA|NOPTR, $32

// Constant Data Block (32 bytes total)
DATA constants<>+0x00(SB)/8, $0x0000000000000000 // Zeros
DATA constants<>+0x08(SB)/8, $0xC0C0C0C0C0C0C0C0 // t2 mask
DATA constants<>+0x10(SB)/8, $0x8080808080808080 // tx mask
DATA constants<>+0x18(SB)/8, $0x3F3F3F3F3F3F3F3F // maskx mask

// - Register usage -
// SI (RSI) - Source pointer (UTF-16)
// DI (RDI) - Destination pointer (UTF-8)
// R9      - Source length (in UTF-16 chars)
// R10     - Original destination pointer (for length calc)
// AX      - Current UTF-16 character/temp
// BX      - Second surrogate char
// CX      - Temp for bit manipulation

// SSE2 Register Usage
//  X0, X1  - Input data (16 UTF-16 chars)
//  X2, X3  - Temp registers for ASCII check
//  X4      - Zero register
//  X15     - ASCII mask (0xFF80)
//  X14     - Surrogate mask (0xF800)

// Control Flow Diagram
//
// Entry
//   |
//   +-> Length >= 16? --No--> process_scalar
//   |
//   Yes
//   |
//   v
// large_block  <-+
//   |            |
//   +-> ASCII? --No--> process_scalar
//   |
//   Yes
//   |
//   +-> Process 16 chars
//   |
//   +-> Length >= 16? --Yes--+
//   |
//   No
//   |
//   v
// medium_block
//   |
//   +-> Length >= 8? --No--> process_scalar
//   |
//   Yes
//   |
//   +-> Process 8 chars
//   |
//   v
// process_scalar
//   |
//   +-> Surrogate? --Yes--> Valid pair? --Yes--> 4-byte
//   |                          |
//   No                        No
//   |                         |
//   |                         v
//   |                    wtf8_encode (3-byte)
//   |
//   +-> ASCII? --Yes--> 1-byte
//   |
//   +-> < 0x800? --Yes--> 2-byte
//   |
//   +-> 3-byte

// Function Declaration:
// TEXT ·utf16ToStringSSE2(SB) - Defines assembly function utf16ToStringSSE2
// NOSPLIT                     - Don't split stack (performance optimization)
// $0-48                      - Stack frame size 0, 48 bytes of arguments
//
// Go function signature:
// func utf16ToStringSSE2(src *uint16, srcLen int, dst []byte) (written int)
//
// Arguments layout (48 bytes total):
// src    +0(FP)   - 8 bytes  - source pointer
// srcLen +8(FP)   - 8 bytes  - source length
// dst    +16(FP)  - 24 bytes - slice (ptr, len, cap)
// ret    +40(FP)  - 8 bytes  - return value
TEXT ·utf16ToStringSSE2(SB), NOSPLIT, $0-48
    // Load arguments into registers
    MOVQ src+0(FP), SI     // Load source pointer into SI
    MOVQ srcLen+8(FP), R9  // Load source length into R9
    MOVQ dst+16(FP), DI    // Load destination pointer into DI
    MOVQ DI, R10           // Save destination start for final length calculation

    // Check if we have enough input for SSE2 processing (16 chars)
    CMPQ R9, $16           // Compare source length with 16
    JL process_scalar      // If length < 16, jump to scalar processing

    // Setup masks (once)
    PCMPEQW X15, X15
    PSLLW $7, X15            // 0xFF80 mask for ASCII
    PCMPEQW X14, X14
    PSRLW $5, X14           // 0xF800 mask for surrogates

large_block:
    // Load 16 UTF-16 chars (32 bytes) into XMM registers
    MOVOU (SI), X0          // Load first 8 chars into X0
    MOVOU 16(SI), X1        // Load next 8 chars into X1

    // Check if all chars are ASCII (<0x80)
    MOVOA X0, X2            // Copy X0 to X2
    MOVOA X1, X3            // Copy X1 to X3
    PAND X15, X2           // Mask with 0xFF80 (keeps high bits)
    PAND X15, X3           // Mask with 0xFF80 (keeps high bits)
    POR X2, X3             // Combine results
    PXOR X4, X4            // Zero X4
    PCMPEQW X3, X4         // Compare with zero (true if ASCII)
    PMOVMSKB X4, AX        // Move mask to GP register
    CMPL AX, $0xFFFF       // Check if all bits set (all ASCII)
    JNE process_scalar     // If not all ASCII, process one by one

    // Pack UTF-16 to UTF-8 (convert 16-bit to 8-bit)
    PACKUSWB X0, X0        // Pack words to bytes in lower half
                        // X0: [char0-7|char0-7]
    PACKUSWB X1, X1        // Pack words to bytes in lower half
                        // X1: [char8-15|char8-15]

    // Store results (8 bytes each)
    MOVQ X0, (DI)          // Store first 8 chars
    MOVQ X1, 8(DI)         // Store next 8 chars at offset 8

    // Advance pointers and counters
    ADDQ $32, SI           // Source += 32 (16 UTF-16 chars * 2 bytes)
    ADDQ $16, DI           // Dest += 16 (16 ASCII chars * 1 byte)
    SUBQ $16, R9           // Remaining chars -= 16
    CMPQ R9, $16           // Check if >= 16 chars left
    JGE large_block        // If yes, process next block

medium_block:
    CMPQ R9, $8
    JL process_scalar

    // Single comparison for remaining length
    SUBQ $8, R9
    JG medium_block

    MOVOU (SI), X0

    // Check for surrogates (0xD800-0xDFFF)
    MOVOA X0, X2
    PAND X14, X2           // Mask with 0xF800
    MOVOA X14, X3
    PSRLW $6, X3          // Create 0xD800 mask
    PCMPEQW X2, X3        // Compare with 0xD800
    PMOVMSKB X3, AX
    TESTL AX, AX
    JNE process_scalar      // If surrogates found, process char by char

    // Load constants for 2-byte sequence
    MOVOU constants<>+0x08(SB), X6  // t2 constant
    MOVOU constants<>+0x10(SB), X7  // tx constant
    MOVOU constants<>+0x18(SB), X8  // maskx constant

    // First byte: 110xxxxx
    MOVOA X0, X1
    PSRLW $6, X1
    POR X6, X1          // OR with t2 constant

    // Second byte: 10xxxxxx
    MOVOA X0, X2
    PAND X8, X2         // AND with maskx constant
    POR X7, X2          // OR with tx constant

    PACKUSWB X1, X1
    PACKUSWB X2, X2
    MOVQ X1, (DI)
    MOVQ X2, 8(DI)

    ADDQ $16, SI
    ADDQ $16, DI

    JG medium_block

process_scalar:
    TESTQ R9, R9
    JZ done

    MOVWQZX (SI), AX         // Load UTF-16 char

    // Check if high surrogate
    CMPW AX, $surr1
    JB regular_char
    CMPW AX, $surr3
    JAE regular_char

    // Check if we have a complete surrogate pair
    CMPW AX, $surr2
    JAE wtf8_encode          // Low surrogate - encode directly
    CMPQ R9, $2              // Need space for pair
    JL wtf8_encode          // Incomplete pair - encode directly

    MOVWQZX 2(SI), BX        // Load second char
    CMPW BX, $surr2
    JB wtf8_encode          // Invalid second char - encode first directly
    CMPW BX, $surr3
    JAE wtf8_encode         // Invalid second char - encode first directly

    // Valid surrogate pair - calculate codepoint
    SUBQ $surr1, AX
    SHLQ $10, AX
    SUBQ $surr2, BX
    ADDQ BX, AX
    ADDQ $surrSelf, AX

    // Write 4-byte UTF-8
    MOVB $t4, (DI)
    MOVQ AX, CX
    SHRQ $18, CX
    ORB CX, (DI)

    MOVQ AX, CX
    SHRQ $12, CX
    ANDB $maskx, CX
    ORB $tx, CX
    MOVB CX, 1(DI)

    MOVQ AX, CX
    SHRQ $6, CX
    ANDB $maskx, CX
    ORB $tx, CX
    MOVB CX, 2(DI)

    MOVQ AX, CX
    ANDB $maskx, CX
    ORB $tx, CX
    MOVB CX, 3(DI)

    ADDQ $4, DI
    ADDQ $4, SI
    SUBQ $2, R9
    JMP process_scalar

wtf8_encode:
    // Use D800 base for both high/low surrogates
    // Math explanation for surrogate encoding:
	// Using 0xD800 base works for both high/low surrogates:
	// High (0xD800): (0xD800-0xD800)>>6 = 0 -> 0xA0|0 = 0xA0
	// Low (0xDC00):  (0xDC00-0xD800)>>6 = 0x10 -> 0xA0|0x10 = 0xB0
    MOVW AX, CX
    SUBW $0xD800, CX    // word-0xD800
    SHRW $6, CX         // >>6
    ORB $0xA0, CX       // 0xA0|result gives correct prefix
    MOVB $0xED, (DI)    // First byte always 0xED
    MOVB CX, 1(DI)      // Second byte has correct prefix
    MOVB AX, CX
    ANDB $0x3F, CX      // Last 6 bits
    ORB $0x80, CX       // Add continuation marker
    MOVB CX, 2(DI)

    ADDQ $3, DI
    ADDQ $2, SI
    DECQ R9
    JMP process_scalar

regular_char:
    CMPW AX, $0x80
    JAE two_byte

    // ASCII
    MOVB AX, (DI)
    INCQ DI
    ADDQ $2, SI
    DECQ R9
    JMP process_scalar

two_byte:
    CMPW AX, $0x800
    JAE three_byte

    // Two-byte encoding
    MOVQ AX, CX
    SHRQ $6, CX
    ORB $t2, CX
    MOVB CX, (DI)

    MOVQ AX, CX
    ANDB $maskx, CX
    ORB $tx, CX
    MOVB CX, 1(DI)

    ADDQ $2, DI
    ADDQ $2, SI
    DECQ R9
    JMP process_scalar

three_byte:
    // Three-byte encoding
    MOVQ AX, CX
    SHRQ $12, CX
    ORB $t3, CX
    MOVB CX, (DI)

    MOVQ AX, CX
    SHRQ $6, CX
    ANDB $maskx, CX
    ORB $tx, CX
    MOVB CX, 1(DI)

    MOVQ AX, CX
    ANDB $maskx, CX
    ORB $tx, CX
    MOVB CX, 2(DI)

    ADDQ $3, DI
    ADDQ $2, SI
    DECQ R9
    JMP process_scalar

done:
    SUBQ R10, DI            // Calculate bytes written
    MOVQ DI, ret+40(FP)     // Return bytes written
    RET
