//go:build windows
// +build windows

package etw

import "strings"

type ProviderDefinition struct {
	Name   string
	Kernel bool
	GUID   string
	Flags  uint32
}

// https://learn.microsoft.com/en-us/windows/win32/etw/nt-kernel-logger-constants
//
// To use a provider, you must enable it in the session creation
// like this:
// kernelSession := etw.NewKernelRealTimeSession(etw.GetKernelProviderFlags("FileIo", "FileIoInit"))
//
// For File rundown events (opcode 36)
// kernelSession := etw.NewKernelRealTimeSession(etw.GetKernelProviderFlags("DiskFileIo"))
// or
// kernelSession := etw.NewKernelRealTimeSession(etw.EVENT_TRACE_FLAG_DISK_IO | etw.EVENT_TRACE_FLAG_DISK_FILE_IO)
//
// Some comments where taken from https://github.com/microsoft/perfview/blob/main/src/TraceEvent/Parsers/KernelTraceEventParser.cs
var (
	KernelProviders = []ProviderDefinition{

		// Logs Advanced Local Procedure call events.
		// https://docs.microsoft.com/en-us/windows/win32/etw/alpc
		{Name: "ALPC",
			Kernel: true,
			GUID:   "{45d8cccd-539f-4b72-a8b7-5c683142609a}",
			Flags:  EVENT_TRACE_FLAG_ALPC},

		//{Name: "ApplicationVerifier", Kernel: true, GUID: "{78d14f17-0105-46d7-bfff-6fbea2f3f358}"},

		// Logs debug output messages from kernel-mode components using DbgPrint/DbgPrintEx
		{Name: "DbgPrint",
			Kernel: true,
			GUID:   "{13976d09-a327-438c-950b-7f03192815c7}",
			Flags:  EVENT_TRACE_FLAG_DBGPRINT},

		// Loads the completion of Physical disk activity.
		// https://docs.microsoft.com/en-us/windows/win32/etw/diskio
		{Name: "DiskIo",
			Kernel: true,
			GUID:   "{3d6fa8d4-fe05-11d0-9dda-00c04fd7ba7c}",
			Flags:  EVENT_TRACE_FLAG_DISK_IO},

		// Logs the initialization of disk IO operations.
		// Generally not TOO volumous (typically less than 1K per second)
		// (Stacks associated with this)
		{Name: "DiskIoInit",
			Kernel: true,
			GUID:   "{3d6fa8d4-fe05-11d0-9dda-00c04fd7ba7c}",
			Flags:  EVENT_TRACE_FLAG_DISK_IO_INIT},

		// Logs the completion of disk IO operations.
		// More info on https://learn.microsoft.com/en-us/windows/win32/etw/diskio
		// Driver* events.
		{Name: "Driver",
			Kernel: true,
			GUID:   "{3d6fa8d4-fe05-11d0-9dda-00c04fd7ba7c}",
			Flags:  EVENT_TRACE_FLAG_DRIVER},

		//{Name: "DiskPerf", Kernel: true, GUID: "{bdd865d1-d7c1-11d0-a501-00a0c9062910}"},
		//{Name: "DriverVerifier", Kernel: true, GUID: "{d56ca431-61bf-4904-a621-00e0381e4dde"},
		//{Name: "EventLog", Kernel: true, GUID: "{b16f9f5e-b3da-4027-9318-adf2b79df73b}"},
		//{Name: "EventTraceConfig", Kernel: true, GUID: "{01853a65-418f-4f36-aefc-dc0f1d2fd235}"},

		// log file FileOperationEnd (has status code) when they complete (even ones that do not actually
		// cause Disk I/O).  (Vista+ only)
		// Generally not TOO volumous (typically less than 1K per second) (No stacks associated with these)
		// https://docs.microsoft.com/en-us/windows/win32/etw/fileio
		{Name: "FileIo",
			Kernel: true,
			GUID:   "{90cbdc39-4a3e-11d1-84f4-0000f80464e3}",
			Flags:  EVENT_TRACE_FLAG_FILE_IO},

		// Logs the mapping of file IDs to actual (kernel) file names.
		// Rundown event with opcode 36
		// https://learn.microsoft.com/en-us/windows/win32/etw/fileio-name
		// FileObject is used to correlate with other FileIo events that reference the same file
		// FileKey persists across system reboots and can be used to track the same file over time
		{Name: "DiskFileIo",
			Kernel: true,
			GUID:   "{90cbdc39-4a3e-11d1-84f4-0000f80464e3}",
			Flags:  EVENT_TRACE_FLAG_DISK_FILE_IO | EVENT_TRACE_FLAG_FILE_IO},

		// log the start of the File I/O operation as well as the end. (Vista+ only)
		// Generally not TOO volumous (typically less than 1K per second)
		{Name: "FileIoInit",
			Kernel: true,
			GUID:   "{90cbdc39-4a3e-11d1-84f4-0000f80464e3}",
			Flags:  EVENT_TRACE_FLAG_FILE_IO_INIT},

		// Enables the map and unmap (excluding image files) event type)
		// Log mapping of files into memory (Win8 and above Only)
		// Generally low volume.
		{Name: "FileIoVAmap",
			Kernel: true,
			GUID:   "{90cbdc39-4a3e-11d1-84f4-0000f80464e3}",
			Flags:  EVENT_TRACE_FLAG_VAMAP},

		//{Name: "GenericMessage", Kernel: true, GUID: "{8d40301f-ab4a-11d2-9a93-00805f85d7c6}"},
		//{Name: "GlobalLogger", Kernel: true, GUID: "{e8908abc-aa84-11d2-9a93-00805f85d7c6}"},
		//{Name: "HardFault", Kernel: true, GUID: "{3d6fa8d2-fe05-11d0-9dda-00c04fd7ba7c}"},

		// Logs native modules loads (LoadLibrary), and unloads (FreeLibrary).
		// https://docs.microsoft.com/en-us/windows/win32/etw/image
		{Name: "ImageLoad",
			Kernel: true,
			GUID:   "{2cb15d1d-5fc1-11d2-abe1-00a0c911f518}",
			Flags:  EVENT_TRACE_FLAG_IMAGE_LOAD},

		//{Name: "MsSystemInformation", Kernel: true, GUID: "{98a2b9d7-94dd-496a-847e-67a5557a59f2}"},

		// Logs all page faults (hard or soft)
		// Can be pretty volumous (> 1K per second)
		// https://docs.microsoft.com/en-us/windows/win32/etw/pagefault-v2
		{Name: "MemoryPageFault",
			Kernel: true,
			GUID:   "{3d6fa8d3-fe05-11d0-9dda-00c04fd7ba7c}",
			Flags:  EVENT_TRACE_FLAG_MEMORY_PAGE_FAULTS},

		// Logs all page faults that must fetch the data from the disk (hard faults)
		{Name: "MemoryHardFault",
			Kernel: true,
			GUID:   "{3d6fa8d3-fe05-11d0-9dda-00c04fd7ba7c}",
			Flags:  EVENT_TRACE_FLAG_MEMORY_HARD_FAULTS},

		// Log Virtual Alloc calls and VirtualFree.   (Vista+ Only)
		// Generally not TOO volumous (typically less than 1K per second)
		{Name: "VirtualAlloc",
			Kernel: true,
			GUID:   "{3d6fa8d3-fe05-11d0-9dda-00c04fd7ba7c}",
			Flags:  EVENT_TRACE_FLAG_VIRTUAL_ALLOC},

		// Device Driver logging (Vista+ only)
		// https://docs.microsoft.com/en-us/windows/win32/etw/process
		{Name: "DPC",
			Kernel: true,
			GUID:   "{ce1dbfb4-137e-4da6-87b0-3f59aa102cbc}",
			Flags:  EVENT_TRACE_FLAG_DPC},

		// log hardware interrupts. (Vista+ only)
		// https://learn.microsoft.com/es-es/windows/win32/etw/isr
		{Name: "Interrupt",
			Kernel: true,
			GUID:   "{ce1dbfb4-137e-4da6-87b0-3f59aa102cbc}",
			Flags:  EVENT_TRACE_FLAG_INTERRUPT},

		// Sampled based profiling (every msec)
		// (expect 1K events per proc per second)
		{Name: "Profile",
			Kernel: true,
			GUID:   "{ce1dbfb4-137e-4da6-87b0-3f59aa102cbc}",
			Flags:  EVENT_TRACE_FLAG_PROFILE},

		// log calls to the OS (Vista+ only)
		// This is VERY volumous (can be > 100K events per second)
		{Name: "Syscall",
			Kernel: true,
			GUID:   "{ce1dbfb4-137e-4da6-87b0-3f59aa102cbc}",
			Flags:  EVENT_TRACE_FLAG_SYSTEMCALL},

		// Logs process starts and stops.
		// https://docs.microsoft.com/en-us/windows/win32/etw/process
		{Name: "Process",
			Kernel: true,
			GUID:   "{3d6fa8d0-fe05-11d0-9dda-00c04fd7ba7c}",
			Flags:  EVENT_TRACE_FLAG_PROCESS},

		// Logs process performance counters (CPU, IO, etc).
		{Name: "ProcessCounters",
			Kernel: true,
			GUID:   "{3d6fa8d0-fe05-11d0-9dda-00c04fd7ba7c}",
			Flags:  EVENT_TRACE_FLAG_PROCESS_COUNTERS},

		// Logs activity to the windows registry.
		// Can be pretty volumous (> 1K per second)
		// https://docs.microsoft.com/en-us/windows/win32/etw/registry
		{Name: "Registry",
			Kernel: true,
			GUID:   "{ae53722e-c863-11d2-8659-00c04fa321a1}",
			Flags:  EVENT_TRACE_FLAG_REGISTRY},

		// Disk I/O that was split (eg because of mirroring requirements) (Vista+ only)
		// https://docs.microsoft.com/en-us/windows/win32/etw/splitio
		{Name: "SplitIo",
			Kernel: true,
			GUID:   "{d837ca92-12b9-44a5-ad6a-3a65b3578aa8}",
			Flags:  EVENT_TRACE_FLAG_SPLIT_IO},

		// Logs TCP/IP network send and receive events.
		// https://docs.microsoft.com/en-us/windows/win32/etw/tcpip
		{Name: "TcpIp",
			Kernel: true,
			GUID:   "{9a280ac0-c8e0-11d1-84e2-00c04fb998a2}",
			Flags:  EVENT_TRACE_FLAG_NETWORK_TCPIP},
		//{Name: "ThermalZone", Kernel: true, GUID: "{a1bc18c0-a7c8-11d1-bf3c-00a0c9062910}"},

		// Logs thread starts and stops.
		// https://docs.microsoft.com/en-us/windows/win32/etw/thread
		{Name: "Thread",
			Kernel: true,
			GUID:   "{3d6fa8d1-fe05-11d0-9dda-00c04fd7ba7c}",
			Flags:  EVENT_TRACE_FLAG_THREAD},

		// Logs thread context switches.
		// (can be > 10K events per second)
		{Name: "CSwitch",
			Kernel: true,
			GUID:   "{3d6fa8d1-fe05-11d0-9dda-00c04fd7ba7c}",
			Flags:  EVENT_TRACE_FLAG_CSWITCH},

		// Thread Dispatcher (ReadyThread) (Vista+ only)
		// (can be > 10K events per second)
		{Name: "Dispatcher",
			Kernel: true,
			GUID:   "{3d6fa8d1-fe05-11d0-9dda-00c04fd7ba7c}",
			Flags:  EVENT_TRACE_FLAG_DISPATCHER},

		//{Name: "TraceError", Kernel: true, GUID: "{398191dc-2da7-11d3-8b98-00805f85d7c6}"},

		// https://docs.microsoft.com/en-us/windows/win32/etw/udpip
		{Name: "UdpIp",
			Kernel: true,
			GUID:   "{bf3a50c5-a9c9-4988-a005-2df0b7c80f80}",
			Flags:  EVENT_TRACE_FLAG_NETWORK_TCPIP},

		//{Name: "WmiEventLogger", Kernel: true, GUID: "{44608a51-1851-4456-98b2-b300e931ee41}"}

		// EVENT_TRACE_FLAG_NO_SYSCONFIG (special, no Windows Kernel/SystemConfig/* rundown events)
	}
)

// Checks if this is a system event trace provider
func IsKernelProvider(term string) bool {
	for _, pd := range KernelProviders {
		if strings.EqualFold(term, pd.Name) || term == pd.GUID {
			return true
		}
	}
	return false
}

func GetKernelProviderFlags(terms ...string) (flags uint32) {
	for _, t := range terms {
		for _, pd := range KernelProviders {
			if strings.EqualFold(t, pd.Name) || t == pd.GUID {
				flags |= pd.Flags
			}
		}

	}
	return
}
