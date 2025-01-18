//go:build windows
// +build windows

package etw

import (
	"syscall"
	"unsafe"
)

// https://learn.microsoft.com/en-us/windows/win32/devnotes/rtlgetversion
// NTSTATUS RtlGetVersion(
//     _Out_ PRTL_OSVERSIONINFOW lpVersionInformation
//   );

// Gets version information about the currently running operating system.
func RtlGetVersion(osvi *OSVERSIONINFOEX) error {
	r1, _, _ := rtlGetVersion.Call(uintptr(unsafe.Pointer(osvi)))
	if r1 == 0 {
		return nil
	}
	return syscall.Errno(r1)
}

// NTSYSAPI NTSTATUS RtlVerifyVersionInfo(
//     [in] PRTL_OSVERSIONINFOEXW VersionInfo,
//     [in] ULONG                 TypeMask,
//     [in] ULONGLONG             ConditionMask
//   );

// The RtlVerifyVersionInfo routine compares a specified set of operating system
// version requirements to the corresponding attributes of the currently running
// version of the operating system.
func RtlVerifyVersionInfo(osvi *OSVERSIONINFOEX, typeMask uint32, conditionMask uint64) error {
	r1, _, _ := rtlVerifyVersionInfo.Call(uintptr(unsafe.Pointer(osvi)), uintptr(typeMask), uintptr(conditionMask))
	if r1 == 0 {
		return nil
	}
	return syscall.Errno(r1)
}
