//go:build windows
// +build windows

package etw

import (
	"unsafe"
)

func GetWindowsVersionInfo() (osvi *OSVERSIONINFOEX) {
	osvi = &OSVERSIONINFOEX{}
	osvi.OSVersionInfoSize = uint32(unsafe.Sizeof(OSVERSIONINFOEX{}))
	// it only returns STATUS_SUCCESS
	RtlGetVersion(osvi)
	return
}

func IsWindowsVersionOrGreater(majorVersion, minorVersion, buildNumber uint32) bool {
    current := GetWindowsVersionInfo()

    if current.MajorVersion > majorVersion {
        return true
    }
    if current.MajorVersion < majorVersion {
        return false
    }

    if current.MinorVersion > minorVersion {
        return true
    }
    if current.MinorVersion < minorVersion {
        return false
    }

    return current.BuildNumber >= buildNumber
}

// VerSetConditionMask sets the specified bits in the condition mask.
// 64-bit mask:
//
// Memory Layout example:
//
// [...unused...][3 bits for BUILD][3 bits for MAYOR][3 bits for MINOR]
//
// The 3 bits for each version part are used to store the condition
func verSetConditionMask(mask uint64, typeBit uint32, condition uint8) uint64 {
	// Ensure condition is valid 0b111
	condition &= VER_CONDITION_MASK
	// Shift condition into position
	mask |= uint64(condition) << (typeBit * VER_NUM_BITS_PER_CONDITION_MASK)
	return mask
}

//! Not working on build version... any condition returns mismatch.
// Windows sometimes fails build-number checks with RtlVerifyVersionInfo.
// This often happens in newer builds of Windows 10/11.
// Use [GetWindowsVersionInfo] instead
// // IsWindowsVersionOrGreater checks if current Windows version meets the specified criteria
// func IsWindowsVersionOrGreaterDebug(majorVersion, minorVersion, buildNumber uint32) bool {
//     osvi := &OSVERSIONINFOEX{
//         OSVersionInfoSize: uint32(unsafe.Sizeof(OSVERSIONINFOEX{})),
//         MajorVersion:      majorVersion,
//         MinorVersion:      minorVersion,
//         BuildNumber:       buildNumber,
//     }

//     var mask uint64
//     var typeMask uint32 = VER_MAJORVERSION | VER_MINORVERSION | VER_BUILDNUMBER

//     mask = verSetConditionMask(mask, VER_MAJORVERSION, VER_GREATER_EQUAL)
//     mask = verSetConditionMask(mask, VER_MINORVERSION, VER_GREATER_EQUAL)
//     mask = verSetConditionMask(mask, VER_BUILDNUMBER, VER_GREATER_EQUAL)

//     err := RtlVerifyVersionInfo(osvi, typeMask, mask)
//     return err == nil
// }
