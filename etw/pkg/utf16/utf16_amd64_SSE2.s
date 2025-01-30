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

// General Purpose Register Usage
// SI (RSI) - Source pointer (UTF-16)
// DI (RDI) - Destination pointer (UTF-8)
// R9      - Source length (in UTF-16 chars)
// R10     - Original destination pointer (for length calc)
// AX      - Current UTF-16 character/temp/comparison results
// BX      - Second surrogate char in surrogate pair processing
// CX      - Temporary register for bit manipulation
// DX      - Unused (available for expansion)
// BP      - Unused (available for expansion)
// R8      - Unused (available for expansion)
// R11-R15 - Unused (available for expansion)

// SSE2 Register Usage
// X0      - Primary input buffer for UTF-16 chars
// X1      - Secondary input buffer (ascii_block_16) / temp (utf8_block_8)
// X2      - Temporary register for comparisons and masks
// X3      - Temporary register for comparisons
// X4      - Zero register for comparisons
// X6      - t2 constant (0xC0) from constants<>
// X7      - tx constant (0x80) from constants<>
// X8      - maskx constant (0x3F) from constants<>
// X14     - Surrogate detection mask (0xF800)
// X15     - ASCII detection mask (0xFF80)
// X5,X9-X13 - Unused (available for expansion)

// Control Flow Diagram
/*
Entry [utf16ToStringSSE2]
   |
   +-> Length >= 16? --No--> utf8_block_8
   |
   Yes
   |
   v
ascii_block_16  <-+
   |           |
   +-> All ASCII? --No--> utf8_block_8
   |
   Yes
   |
   +-> Process 16 chars
   |
   +-> Length >= 16? --Yes-+
   |
   No
   |
   v
utf8_block_8
   |
   +-> Length >= 8? --No--> char_by_char
   |
   Yes
   |
   +-> Has surrogates? --Yes--> char_by_char
   |
   No
   |
   +-> Process 8 chars
   |
   +-> More chars? --Yes--> utf8_block_8
   |
   No
   |
   v
char_by_char <-+
   |             |
   +-> No chars? --Yes--> done
   |
   +-> Is surrogate? --Yes--> Valid pair? --Yes--> 4-byte --+
   |                             |                          |
   |                             No                         |
   |                             |                         |
   |                             v                         |
   |                        encode_surrogate_wtf8 (3-byte) -------->-+
   |                                                       |
   +-> < 0x80? --Yes--> 1-byte ASCII ------------------>--+
   |                                                       |
   +-> < 0x800? --Yes--> 2-byte ---------------------->--+
   |                                                      |
   +-> 3-byte --------------------------------------->----+
   |                                                      |
   +------------------------------------------------->--+

done
*/

// Function Declaration:
// TEXT ·utf16ToStringSSE2(SB) - Defines assembly function utf16ToStringSSE2
// NOSPLIT                     - Don't split stack (performance optimization)
// $0-48                       - Stack frame size 0, 48 bytes of arguments
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
    JL char_by_char        // If length < 16, jump to scalar processing

    // Setup masks (once)
    PCMPEQW X15, X15
    PSLLW $7, X15            // 0xFF80 mask for ASCII
    PCMPEQW X14, X14
    PSRLW $5, X14           // 0xF800 mask for surrogates

// ascii_block_16: Processes 16 UTF-16 characters at once using SSE2
// Optimized path for ASCII-only content (characters < 0x80)
ascii_block_16:
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
    JNE char_by_char     // If not all ASCII, process one by one

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
    JGE ascii_block_16        // If yes, process next block

// utf8_block_8: Processes 8 UTF-16 characters at once
// Handles non-ASCII characters that don't contain surrogate pairs
utf8_block_8:
    CMPQ R9, $8                    // Check if at least 8 chars remain
    JL char_by_char              // If less than 8 chars, process one by one

    SUBQ $8, R9                    // Decrement counter by 8 chars
    JG utf8_block_8                // If more chars remain, continue processing

    MOVOU (SI), X0                 // Load 8 UTF-16 chars into XMM0

    // Check for surrogate pairs
    MOVOA X0, X2                   // Copy input to X2 for surrogate check
    PAND X14, X2                   // Mask with 0xF800 to isolate surrogate bits
    MOVOA X14, X3                  // Copy surrogate mask to X3
    PSRLW $6, X3                   // Shift right to create 0xD800 mask
    PCMPEQW X2, X3                 // Compare with 0xD800
    PMOVMSKB X3, AX                // Extract comparison result to AX
    TESTL AX, AX                   // Check if any surrogates found
    JNE char_by_char             // If surrogates present, process char by char

    // Load UTF-8 encoding constants
    MOVOU constants<>+0x08(SB), X6 // Load t2 constant (0xC0)
    MOVOU constants<>+0x10(SB), X7 // Load tx constant (0x80)
    MOVOU constants<>+0x18(SB), X8 // Load maskx constant (0x3F)

    MOVOA X0, X1                   // Copy input for first byte calculation
    PSRLW $6, X1                   // Shift right 6 bits for first byte
    POR X6, X1                     // Add 110xxxxx prefix

    MOVOA X0, X2                   // Copy input for second byte calculation
    PAND X8, X2                    // Mask for lower 6 bits
    POR X7, X2                     // Add 10xxxxxx prefix

    PACKUSWB X1, X1                // Pack first bytes into lower 8 bytes
    PACKUSWB X2, X2                // Pack second bytes into lower 8 bytes
    MOVQ X1, (DI)                  // Store first bytes
    MOVQ X2, 8(DI)                 // Store second bytes

    ADDQ $16, SI                   // Advance source pointer by 16 bytes
    ADDQ $16, DI                   // Advance destination pointer by 16 bytes

    JG utf8_block_8                // If more chars remain, continue processing

// char_by_char: Character-by-character processing
// Handles surrogate pairs and general UTF-16 to UTF-8 conversion
char_by_char:
    TESTQ R9, R9                  // Test if any characters remain (R9 = char count)
    JZ done                       // If zero, jump to done

    MOVWQZX (SI), AX              // Load UTF-16 char into AX with zero extension

    // Surrogate pair detection
    CMPW AX, $surr1               // Compare with high surrogate start (0xD800)
    JB encode_ascii               // If below 0xD800, process as regular char
    CMPW AX, $surr3               // Compare with surrogate end (0xE000)
    JAE encode_ascii              // If >= 0xE000, process as regular char

    // Surrogate pair processing
    CMPW AX, $surr2              // Compare with low surrogate start (0xDC00)
    JAE encode_surrogate_wtf8              // If >= 0xDC00, it's an unpaired low surrogate
    CMPQ R9, $2                  // Check if we have space for complete pair
    JL encode_surrogate_wtf8               // If not, encode current char as standalone

    MOVWQZX 2(SI), BX            // Load second char of potential pair
    CMPW BX, $surr2              // Compare with low surrogate start
    JB encode_surrogate_wtf8               // If below 0xDC00, invalid second char
    CMPW BX, $surr3              // Compare with surrogate end
    JAE encode_surrogate_wtf8              // If >= 0xE000, invalid second char

    // Valid surrogate pair conversion to Unicode code point
    SUBQ $surr1, AX              // Subtract high surrogate base
    SHLQ $10, AX                 // Shift left by 10 bits
    SUBQ $surr2, BX              // Subtract low surrogate base
    ADDQ BX, AX                  // Combine high and low surrogate values
    ADDQ $surrSelf, AX           // Add surrogate pair offset (0x10000)

    // Write 4-byte UTF-8 sequence
    MOVB $t4, (DI)               // Write first byte prefix (11110xxx)
    MOVQ AX, CX                  // Copy code point for manipulation
    SHRQ $18, CX                 // Get bits 18-20
    ORB CX, (DI)                 // Complete first byte

    MOVQ AX, CX                  // Copy code point again
    SHRQ $12, CX                 // Get bits 12-17
    ANDB $maskx, CX              // Mask to get 6 bits
    ORB $tx, CX                  // Add continuation byte prefix
    MOVB CX, 1(DI)               // Store second byte

    MOVQ AX, CX                  // Copy code point again
    SHRQ $6, CX                  // Get bits 6-11
    ANDB $maskx, CX              // Mask to get 6 bits
    ORB $tx, CX                  // Add continuation byte prefix
    MOVB CX, 2(DI)               // Store third byte

    MOVQ AX, CX                  // Copy code point one last time
    ANDB $maskx, CX              // Get final 6 bits
    ORB $tx, CX                  // Add continuation byte prefix
    MOVB CX, 3(DI)               // Store fourth byte

    ADDQ $4, DI                  // Advance destination by 4 bytes
    ADDQ $4, SI                  // Advance source by 4 bytes (2 UTF-16 chars)
    SUBQ $2, R9                  // Decrease char count by 2
    JMP char_by_char           // Continue processing next character

// encode_surrogate_wtf8: Encodes individual surrogate values as 3-byte UTF-8 sequences
// Used for incomplete or invalid surrogate pairs
encode_surrogate_wtf8:
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
    JMP char_by_char

// encode_ascii: Processes regular (non-surrogate) UTF-16 characters
// Routes to appropriate encoding length (ASCII, 2-byte, or 3-byte)
encode_ascii:
    CMPW AX, $0x80          // Compare char with 0x80 (ASCII boundary)
    JAE encode_2byte            // If char >= 0x80, jump to encode_2byte encoding

    // ASCII path (single byte encoding)
    MOVB AX, (DI)           // Store the ASCII char directly to destination
    INCQ DI                 // Increment destination pointer by 1 byte
    ADDQ $2, SI             // Advance source pointer by 2 bytes (UTF-16 char size)
    DECQ R9                 // Decrement remaining character count
    JMP char_by_char      // Continue with next character


// encode_2byte: Encodes characters in range 0x80-0x7FF as 2-byte UTF-8 sequences
encode_2byte:
    CMPW AX, $0x800         // Compare char with 0x800
    JAE encode_3byte          // If char >= 0x800, jump to encode_3byte encoding

    // First byte: 110xxxxx
    MOVQ AX, CX             // Copy character to CX for manipulation
    SHRQ $6, CX             // Shift right 6 bits to get high bits
    ORB $t2, CX             // OR with 0xC0 to add 110xxxxx prefix
    MOVB CX, (DI)           // Store first byte to destination

    // Second byte: 10xxxxxx
    MOVQ AX, CX             // Copy character again to CX
    ANDB $maskx, CX         // Mask with 0x3F to get low 6 bits
    ORB $tx, CX             // OR with 0x80 to add 10xxxxxx prefix
    MOVB CX, 1(DI)          // Store second byte to destination+1

    ADDQ $2, DI             // Advance destination pointer by 2 bytes
    ADDQ $2, SI             // Advance source pointer by 2 bytes (UTF-16 char size)
    DECQ R9                 // Decrement remaining character count
    JMP char_by_char      // Continue with next character

// encode_3byte: Encodes characters in range 0x800-0xFFFF as 3-byte UTF-8 sequences
encode_3byte:
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
    JMP char_by_char

done:
    SUBQ R10, DI            // Calculate bytes written
    MOVQ DI, ret+40(FP)     // Return bytes written
    RET
