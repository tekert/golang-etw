[![GoDoc](https://pkg.go.dev/badge/github.com/0xrawsec/golang-etw)](https://pkg.go.dev/github.com/0xrawsec/golang-etw/etw?GOOS=windows)
![Version](https://img.shields.io/github/v/tag/0xrawsec/golang-etw?label=version)
[![Coverage](https://raw.githubusercontent.com/0xrawsec/golang-etw/master/.github/coverage/badge.svg)](https://raw.githubusercontent.com/tekert/golang-etw/refs/heads/fork/.github/coverage/coverage.txt)

Pure Golang (no need to enable CGO) library to consume ETW logs.

## Examples

See [./examples](./examples)

```go
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/0xrawsec/golang-etw/etw"
)

func main() {
	// ETW needs a trace to be created before being able to consume from
	// it. Traces can be created using golang-etw or they might be already
	// existing (created from an autologgers for instance) like Eventlog-Security.

	// Creating the trace (producer part)
	s := etw.NewRealTimeSession("TestingGoEtw")

	// We have to stop the session or it will be kept alive and session name
	// will not be available anymore for next calls
	defer s.Stop()

	// we need to enable the trace to collect logs from given providers
	// several providers can be enabled per trace, in this example we
	// enable only one provider
	if err := s.EnableProvider(etw.MustParseProvider("Microsoft-Windows-Kernel-File")); err != nil {
		panic(err)
	}

	// Consuming from the trace
	c := etw.NewConsumer(context.Background())

	defer c.Stop()

	c.FromSessions(s)

	// When events are parsed they get sent to Consumer's
	// Events channel by the default EventCallback method
	// EventCallback can be modified to do otherwise
	go func() {
		var b []byte
		var err error
		for e := range c.Events {
			if b, err = json.Marshal(e); err != nil {
				panic(err)
			}
			fmt.Println(string(b))
		}
	}()

	if err := c.Start(); err != nil {
		panic(err)
	}

	time.Sleep(5 * time.Second)

	if c.Err() != nil {
		panic(c.Err())
	}

}
```

## Overview of how ETW works:
This is my best attempt to explain the worst designed API created by microsoft as simply as i can

There are a few of general terms used in ETW:
- "Trace"
- "Trace Session"/"Session"
- "Trace controller"
- "Consumer"
- "Provider"

Here we go:  

#### Sessions
A Trace Session is a buffer allocated by you using etw syscalls (can be paged, non paged, real time, circular buffer, writen to a file, etc) there are many forms of session properties you can select, allocated using StartTrace, you provide a name or use another existing trace for this new Session to form a Trace Session.  

For example in code, for a real time session (meaning we want to process events that arrive in this session as soon as they arrive in our buffer) this is as simple as calling:  
```
s := etw.NewRealTimeSession("TestingGoEtw")
defer s.Stop()
```

#### Providers

An Provider is the logical entity that raises events and writes them to an Session  
For example, to assing providers to the real time session we created earlier, we use for example:  
``` s.EnableProvider(etw.MustParseProvider("Microsoft-Windows-Kernel-Disk") ```  

We can attach another provider to the trace now with keywords:  
```s.EnableProvider(etw.MustParseProvide("Microsoft-Windows-Kernel-File:0xff:13,14:0x80:0x00")```  

`":0xff:13,14:0x80:0x00"` after the provider name means:  

`LogLevel as hex`:`<EventIDs as ints separed by comma>`:`MatchAnyKeyword in HEX`:`MatchAllKeyword in HEX`

Everything is optional.

You can see the accepted levels and keywords for this example using  
> `logman query providers Microsoft-Windows-Kernel-File`  
or  
> `Wevtutil gp "Microsoft-Windows-Kernel-File"`

Definitions:  

- `LogLevel as hex`  (Default is All levels = 0xFF)  
The event level defines the event's severity or importance and is a
primary means for filtering events. Microsoft-defined levels (in
evntrace.h and  winmeta.h) are 1 (critical/fatal), 2 (error),
3 (warning), 4 (information), and 5 (verbose). Levels 6-9 are reserved.
Level 0 means the event is always-on (will not be filtered by level).
For a provider, a lower level means the event is more important. An
event with level 0 will always pass any level-based filtering.
For a consumer, a lower level means the session's filter is more
restrictive. However, setting a session's level to 0 disables level
filtering (i.e. session level 0 is the same as session level 255).  
Custom logging levels can also be defined, but levels 6–15 are reserved.  
More than one logging level can be captured by ORing respective levels;  
supplying 255 (0xFF) is the standard method of capturing all supported logging levels.  
More info [here](https://learn.microsoft.com/en-us/windows/win32/wes/eventmanifestschema-leveltype-complextype#remarks)  

- `<EventIDs as ints separed by comma>`  (Default is to include ALL events IDs)   
 You can check the event ids a provider supports by looking at it's manifest with [ETW Explorer][etw-explorer] or with the `Wevtutil gp` command previously executed, these IDs are used as fast filtering on `EnableTraceEx2`  
 This is used in this library as follows:  
From Doc at: [EVENT_TRACE_PROPERTIES](https://learn.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-enable_trace_parameters) -> FilterDescCount  
FilterDescCount -> [EVENT_FILTER_DESCRIPTOR](https://learn.microsoft.com/en-us/windows/win32/api/evntprov/ns-evntprov-event_filter_descriptor) -> EVENT_FILTER_TYPE_EVENT_ID  
 This feature allows enabling or disabling filtering for a list of events. The provided filter includes a EVENT_FILTER_EVENT_ID structure that contains an array of event IDs and a Boolean value that indicates whether to enable or disable from filtering for the specified events. Each event write call (from a  provider) will go through this array quickly to find out whether enable or disable logging the event.  
 This is faster than filtering at the Consumer.

- `MatchAnyKeyword in HEX` (Default is to include ALL events = 0x00)  
The event is written by the provider if any of the event's keyword bits match any of the bits set in this mask or if the event has no keyword bits set  
The keywords can be inspected by using the `logman` or `Wevtutil gp` command previously executed (look for the mask/hex form)  
0x80 for this provider means: KERNEL_FILE_KEYWORD_CREATE  
An event can have many keywords, if any event contains the KERNEL_FILE_KEYWORD_CREATE flag, then it's sent by the provider.  
Filtering at kernel level is inherently faster than user mode filtering (following the parsing process).

- `MatchAllKeyword in HEX` (Default is to include ALL events = 0x00)  
Bitmask where for those events that matched the "MatchAnyKeyword" case, the event is written by the provider only if all of the bits in the "MatchAllKeyword" mask exist in the event's keyword bitmask or if the event has no keyword bits set.  
This value is frequently set to 0.  
Note that this mask is not used if Keywords(Any) is set to zero.  

The evntprov.h source header have the best doc on this:  
```cpp
// An event will pass the session's keyword filtering  
// if the following expression is true:  
event.Keyword == 0 || (  
(event.Keyword & session.KeywordAny) != 0 &&  
(event.Keyword & session.KeywordAll) ==  session.KeywordAll).  
// In other words, uncategorized events (events with no keywords set) always pass keyword filtering, and categorized events pass if they match any keywords in KeywordAny and match all keywords in KeywordAll.  
```

More info in  
[evntprov.h](https://github.com/tpn/winsdk-10/blob/9b69fd26ac0c7d0b83d378dba01080e93349c2ed/Include/10.0.16299.0/shared/evntprov.h#L284)  
[Keywords](https://learn.microsoft.com/en-us/windows/win32/wes/defining-keywords-used-to-classify-types-of-events)  
An also at [EnableTraceEx2](https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-enabletraceex2#remarks)  

#### Writing events to a .etl file
Usually when using a provider to output events to file, you create an etl tracefile using windows tools, like logman command.  
For example, let's start with the special Kernel Trace:
> logman query providers "Windows Kernel Trace"  

You can see the keywords used for filtering events.
To log events you can use the keywords in `logman` like this:
>logman start "NT Kernel Logger" –p "Windows Kernel Trace" (process,thread,img,disk,net,registry) –o systemevents.etl –ets

And when you want to stop use:
> logman stop "NT Kernel Logger"

NOTE: Use filtering, some events can write a gigabyte of data in a few seconds.

You can also create kernel etl traces using Performance Monitor -> System Performance but it select only a few keywords by default,   
NOTE: events like context switches can only be read from the NT Kernel Logger trace (with its "Windows Kernel Trace" only provider). The Manifest "Kernel" providers don't have it.

You can use [PerfView](https://github.com/microsoft/perfview) to open that .etl file and see the events from a GUI for easy debugging.

You assign providers to write to your trace (buffer or file), you can filter events using keywords (that are implemented on the provider side before an event is formed, thus is the fastest way to filter events) or filter events once the event is formed, this library currently only support filter for event IDs.  
A Manifest provider is just a Provider that defines what events it can output and what the properties in those events mean. You can browse the manifest providers installed in you system using [ETW Explorer][etw-explorer]


#### Trace Controller
The Trace Controller is this software doing the trace control between providers and the Session, the ouput of events for this session is the Trace, the Session would be the broader concept of forming the connection aka Trace Session.

#### Trace Session
Finally, once the providers you selected are Enabled and writing events to your Session it means you formed an Trace Session, the other case is to use an existing Trace and you wanted you hook on it a read it's event directly, that means you want to read from a Trace, no session (buffer) is needed in that case.  
Reading the events the Trace is collecting means to Consume from it.

#### Consumer
The Consumpion is that act of Opening a Trace with `OpenTrace` and then processing it (consumer has to open first) with a blocking call to `ProcessTrace` in a new thread/goroutine, setting callbacks to read stats from the buffer you allocated and another callback to finally receive the actual events (parsing the events is another history and doing it efficiently is another) but this library already handles it for easy consumption.  
``` 
c := etw.NewConsumer(context.Background()) 
defer c.Stop()
c.FromSessions(s)
// ...
// Create goroutine to recive events
// ...
// Start processing events from traces, any non opened trace is opened.
if err := c.Start(); err != nil {
	panic(err)
}

```  
`c.FromSessions` Registers the real time trace names that we created with `NewRealTimeSession`, in this case "TestingGoEtw"  

`c.Start`  Opens the trace session that where registered (in this case only "TestingGoEtw") and starts Processing them in a new goroutine.

NOTE: If for example, "TestingGoEtw" already existed and it was not closed, mean you only need to consume from it, no need to create another Session.
`c.FromTraceNames` can do that.


The context here is just a means to sync the goroutines on exit.  
Each one will contain traces with a blocking `ProcessTrace` func that will call the previouly defined callbacks on the same thread/goroutine where `ProcessTrace` is blocking from. Meaning only one event has to be processed at a time, if an event is not proceced fast enough, the Trace Session buffer capacity would fill and events could be lost.  
More info on buffer sizes when creating the `Session` at [EVENT_TRACE_PROPERTIES_V2](https://learn.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-event_trace_properties_v2]) and [here][ETW Buffer Configuration-WWM]

There are 3 ways to check for Events lost that is not deprecated in modern ETW.  

- One is to catch event that come from a special Provider ID (the process that generated the event) GUID that tracks events lost in a real-time session.  
 
- Another is to read the [EVENT_TRACE_LOGFILE](https://learn.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-event_trace_logfilea) header when it arrives to [BufferCallback](https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nc-evntrace-pevent_trace_buffer_callbacka) (ETW calls the callback after delivering all events in the buffer to the consumer) the [TRACE_LOGFILE_HEADER](https://learn.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-trace_logfile_header) will have our EventsLost field.  
Do not use the EventLost field from the `EVENT_TRACE_LOGFILE`.

- Manually by using `ControlTrace` with ControlCode parameter to `EVENT_TRACE_CONTROL_QUERY` that will return a [`EVENT_TRACE_PROPERTIES_V2`](https://learn.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-event_trace_properties_v2)  

I still don't know if there is any difference between the 3 methods apart from convenience.

#### Stopping ETW Traces
To stop this, you have to stop two things.  
`The Provider -> Trace` connection (aka `Session`)  
and the  
`Trace -> Consumer` connection  (aka `Consumer`)  

- `The Provider -> Trace Session` is usually a Real Time `Trace Session` meaning you want to receive events in real time as the provider outputs them, can also be a memory circular buffer, there are special Kernel/System trace sessions that only admit 1 consumer (`ProcessTrace`) at at time, For example the "NT Kernel Logger" `Trace` already exists and can't be connected to any providers except the "Windows Kernel Trace" provider wich is already connected by default.  
To stop the connection you use the `ControlTrace` syscall.  
In this library is simply deferring a call `Stop()` for a `Session`.  

Is **important** to close this as it can persist even if the program crashes or exits abnormally.  
From the command line you can close a trace session with: (replace `<TRACE_NAME>` with your trace name)
>  logman stop <TRACE_NAME> -ets  

You can also inspect the current opened traces with:
> logman -ets

- `The Trace -> Consumer` is Stopped when `ProcessTrace` blocking call ends, can be stopped using two methods, returning 0 from a the buffer callback or also using `CloseTrace` syscall, or termitating the `Trace Controller` (this library process).  
In this library it the simple act of deferring a call to `Stop()` for a `Consumer`.

- The `Log File -> Consumer` connection is a Trace (etl trace file to consume from) -> Consumer, to close them you use the same `CloseTrace`  
In this library it the simple act of deferring a call to `Stop()` for a `Consumer` or waiting to the file read to end.  

--------------

Some sanitized IA definitions: (because not even microsoft docs and blogs defines this so clearly) except the deleted conceptual tutorial from microsoft, you can read it below [ETW Framework Conceptual Tutorial]

### Session
- In ETW, "Session" often refers to a Trace Session, but it is a broader term that could include the conceptual idea of managing providers, consumers, and log files.
- Usage Context:
Sometimes used interchangeably with "Trace Session."
May refer to the overall lifecycle of event tracing, including starting, stopping, and managing the session.

### Trace Session
- A Trace Session is the active logging mechanism that collects events from one or more providers and writes them to a log file or delivers them in real-time to a consumer.
- Key Features:
It's a container for ETW events.
Can collect events from multiple providers.
Configured using EventTraceProperties and started with StartTrace.

### Trace
- A Trace typically refers to the actual process of recording events during a Trace Session.
- Key Points:
It’s the action of capturing data.
The term is more abstract and refers to the output of the session (e.g., a log file or real-time events).
Examples:
"Capturing a trace" means enabling a session and collecting events.

### Trace Controller
- A Trace Controller is the component or entity responsible for managing trace sessions. It issues commands to start, stop, or configure trace sessions.
- Key Responsibilities:
Configures trace sessions using APIs like StartTrace, ControlTrace, and StopTrace.
Enables or disables providers using APIs like EnableTraceEx2.
Ensures proper setup of log files, real-time delivery, and session settings.

## Related Documentation

- (Best) [ETW Framework Conceptual Tutorial][ETW Framework Conceptual Tutorial-WMM]
(Actually deleted by microsoft... using wayback machine)
- [Instrumenting Your Code with ETW](https://learn.microsoft.com/en-us/windows-hardware/test/weg/instrumenting-your-code-with-etw)

- [Core OS Events in Windows, Part 1](https://learn.microsoft.com/en-us/archive/msdn-magazine/2009/september/core-os-events-in-windows-7-part-1)
- [Core OS Events in Windows, Part 2](https://learn.microsoft.com/en-us/archive/msdn-magazine/2009/october/core-instrumentation-events-in-windows-7-part-2)
- [About Event Tracing, Provider Types](https://learn.microsoft.com/en-us/windows/win32/etw/about-event-tracing)
- [How are Events Created](https://learn.microsoft.com/en-us/windows/win32/etw/event-metadata-overview)


- [ETW API](https://learn.microsoft.com/en-us/windows/win32/api/evntrace/)

- [Advanced ETWSession Configuration][ETW Buffer Configuration-WWM] (Actually deleted by microsoft... using wayback machine)

## Related Work

- [ETW Explorer][etw-explorer]
(use this to browse manifest providers in your system)
- [ETWProviders](https://github.com/repnz/etw-providers-docs)

[etw-explorer]: https://github.com/zodiacon/EtwExplorer

[ETW Framework Conceptual Tutorial]: https://learn.microsoft.com/en-us/message-analyzer/etw-framework-conceptual-tutorial
[ETW Framework Conceptual Tutorial-WMM]: http://web.archive.org/web/20240331153956/https://learn.microsoft.com/en-us/message-analyzer/etw-framework-conceptual-tutorial

[ETW Buffer Configuration]: https://docs.microsoft.com/en-us/message-analyzer/specifying-advanced-etw-session-configuration-settings
[ETW Buffer Configuration-WWM]: http://web.archive.org/web/20220120013651/https://docs.microsoft.com/en-us/message-analyzer/specifying-advanced-etw-session-configuration-settings