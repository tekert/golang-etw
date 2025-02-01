//go:build windows

package etw

import (
	"syscall"
)

// TODO(tekert): use kernel32.dll instead, GetVersionExW, there a more useful functions there.

var (
	modntdll             = syscall.NewLazyDLL("ntdll.dll")
	rtlGetVersion        = modntdll.NewProc("RtlGetVersion")
	rtlVerifyVersionInfo = modntdll.NewProc("RtlVerifyVersionInfo")
)
