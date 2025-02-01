//go:build windows

package etw

// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_osversioninfoexw
//
// typedef struct _OSVERSIONINFOEXW {
// 	ULONG  dwOSVersionInfoSize;
// 	ULONG  dwMajorVersion;
// 	ULONG  dwMinorVersion;
// 	ULONG  dwBuildNumber;
// 	ULONG  dwPlatformId;
// 	WCHAR  szCSDVersion[128];
// 	USHORT wServicePackMajor;
// 	USHORT wServicePackMinor;
// 	USHORT wSuiteMask;
// 	UCHAR  wProductType;
// 	UCHAR  wReserved;
//   } OSVERSIONINFOEXW, *POSVERSIONINFOEXW, *LPOSVERSIONINFOEXW, RTL_OSVERSIONINFOEXW, *PRTL_OSVERSIONINFOEXW;
//
// Size: 284 bytes

// The RTL_OSVERSIONINFOEXW structure contains operating system version information.
type OSVERSIONINFOEX struct {
	OSVersionInfoSize uint32
	MajorVersion      uint32
	MinorVersion      uint32
	BuildNumber       uint32
	PlatformId        uint32
	CSDVersion        [128]uint16
	ServicePackMajor  uint16
	ServicePackMinor  uint16
	SuiteMask         uint16
	ProductType       byte
	Reserved          byte
}

const (
	/* RtlVerifyVersionInfo() ComparisonType */
	VER_EQUAL         = 1
	VER_GREATER       = 2
	VER_GREATER_EQUAL = 3
	VER_LESS          = 4
	VER_LESS_EQUAL    = 5
	VER_AND           = 6
	VER_OR            = 7

	VER_CONDITION_MASK              = 7
	VER_NUM_BITS_PER_CONDITION_MASK = 3

	/* RtlVerifyVersionInfo() TypeMask */
	VER_MINORVERSION     = 0x0000001
	VER_MAJORVERSION     = 0x0000002
	VER_BUILDNUMBER      = 0x0000004
	VER_PLATFORMID       = 0x0000008
	VER_SERVICEPACKMINOR = 0x0000010
	VER_SERVICEPACKMAJOR = 0x0000020
	VER_SUITENAME        = 0x0000040
	VER_PRODUCT_TYPE     = 0x0000080
)
