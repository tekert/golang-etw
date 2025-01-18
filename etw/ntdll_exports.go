//go:build windows
// +build windows

package etw

import (
	"syscall"
)

var (
	modntdll = syscall.NewLazyDLL("ntdll.dll")
    rtlGetVersion = modntdll.NewProc("RtlGetVersion")
	rtlVerifyVersionInfo = modntdll.NewProc("RtlVerifyVersionInfo")
)
