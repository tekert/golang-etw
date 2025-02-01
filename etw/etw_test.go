//go:build windows
// +build windows

package etw

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/0xrawsec/toast"
)

const (
	// providers
	SysmonProvider           = "{5770385F-C22A-43E0-BF4C-06F5698FFBD9}"
	KernelMemoryProviderName = "{D1D93EF7-E1F2-4F45-9943-03D245FE6C00}"
	KernelFileProviderName   = "Microsoft-Windows-Kernel-File"
	// sessions
	EventlogSecurity = "Eventlog-Security" // Need special permissions
)

func init() {
	//rand.Seed(time.Now().UnixNano())
	// As of Go 1.20, the global random number generator is automatically seeded
}

func randBetween(min, max int) (i int) {
	for ; i < min; i = rand.Int() % max {
	}
	return
}

func TestIsKnownProvider(t *testing.T) {
	t.Parallel()

	tt := toast.FromT(t)

	tt.Assert(IsKnownProvider("Microsoft-Windows-Kernel-File"))
	tt.Assert(!IsKnownProvider("Microsoft-Windows-Unknown-Provider"))
}

func TestProducerConsumer(t *testing.T) {
	var prov Provider
	var err error

	eventCount := 0
	tt := toast.FromT(t)

	// Producer part
	ses := NewRealTimeSession("GolangTest")
	defer ses.Stop()

	prov, err = ParseProvider(KernelFileProviderName + ":0xff:12,13,14,15,16")
	tt.CheckErr(err)
	// enabling provider
	tt.CheckErr(ses.EnableProvider(prov))
	// starting producer
	tt.CheckErr(ses.Start())
	// checking producer is running
	tt.Assert(ses.IsStarted())

	// Consumer part
	c := NewConsumer(context.Background()).FromSessions(ses) //.FromTraceNames(EventlogSecurity)

	// we have to declare a func otherwise c.Stop seems to be called
	defer func() { tt.CheckErr(c.Stop()) }()
	// starting consumer
	tt.CheckErr(c.Start())

	start := time.Now()
	// consuming events in Golang
	go func() {
		//for e := range c.Events {
		c.ProcessEvents(func(e *Event) {
			eventCount++

			if e.System.Provider.Name == KernelFileProviderName {
				tt.Assert(e.System.EventID == 12 ||
					e.System.EventID == 13 ||
					e.System.EventID == 14 ||
					e.System.EventID == 15 ||
					e.System.EventID == 16)
			}

			_, err := json.Marshal(&e)
			tt.CheckErr(err)
			//t.Log(string(b))
		})
	}()
	// sleeping
	time.Sleep(5 * time.Second)

	// stopping consumer
	tt.CheckErr(c.Stop())
	delta := time.Since(start)
	eps := float64(eventCount) / delta.Seconds()
	t.Logf("Received: %d events in %s (%d EPS)", eventCount, delta, int(eps))

	// checking any consumer error
	tt.CheckErr(c.LastError())
}

func TestKernelSession(t *testing.T) {
	tt := toast.FromT(t)
	eventCount := 0

	traceFlags := []uint32{
		// Trace process creation / termination
		//EVENT_TRACE_FLAG_PROCESS,
		// Trace image loading
		EVENT_TRACE_FLAG_IMAGE_LOAD,
		// Trace file operations
		//EVENT_TRACE_FLAG_FILE_IO_INIT,
		//EVENT_TRACE_FLAG_ALPC,
		EVENT_TRACE_FLAG_REGISTRY,
	}

	// producer part
	kp := NewKernelRealTimeSession(traceFlags...)

	// starting kernel producer
	tt.CheckErr(kp.Start())
	// checking producer is started
	tt.Assert(kp.IsStarted())

	// consumer part
	c := NewConsumer(context.Background()).FromSessions(kp)

	// we have to declare a func otherwise c.Stop seems to be called
	defer func() { tt.CheckErr(c.Stop()) }()

	tt.CheckErr(c.Start())

	start := time.Now()
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		//for e := range c.Events {
		c.ProcessEvents(func(e *Event) {
			eventCount++

			_, err := json.Marshal(&e)
			tt.CheckErr(err)
			//t.Log(string(b))
		})
	}()

	time.Sleep(5 * time.Second)

	tt.CheckErr(c.Stop())
	tt.CheckErr(kp.Stop())
	wg.Wait()

	delta := time.Since(start)
	eps := float64(eventCount) / delta.Seconds()
	t.Logf("Received: %d events in %s (%d EPS)", eventCount, delta, int(eps))
}

func TestEventMapInfo(t *testing.T) {
	tt := toast.FromT(t)
	eventCount := 0

	prod := NewRealTimeSession("GolangTest")

	mapInfoChannels := []string{
		"Microsoft-Windows-ProcessStateManager",
		"Microsoft-Windows-DNS-Client",
		"Microsoft-Windows-Win32k",
		"Microsoft-Windows-RPC",
		"Microsoft-Windows-Kernel-IoTrace"}

	for _, c := range mapInfoChannels {
		t.Log(c)
		prov, err := ParseProvider(c)
		tt.CheckErr(err)
		tt.CheckErr(prod.EnableProvider(prov))
	}

	// starting producer
	tt.CheckErr(prod.Start())
	// checking producer is running
	tt.Assert(prod.IsStarted())

	defer prod.Stop()

	// consumer part
	fakeError := fmt.Errorf("fake")

	c := NewConsumer(context.Background()).FromSessions(prod)
	// reducing size of channel so that we are obliged to skip events
	c.Events = make(chan []*Event)
	c.EventsConfig.BatchSize = 1
	c.EventPreparedCallback = func(erh *EventRecordHelper) error {

		erh.TraceInfo.EventMessage()
		erh.TraceInfo.ActivityIDName()
		erh.TraceInfo.RelatedActivityIDName()

		erh.Skip()

		for _, p := range erh.Properties {
			// calling those two method just to test they don't cause memory corruption
			p.evtPropInfo.Count()
			p.evtPropInfo.CountPropertyIndex()
			if p.evtPropInfo.MapNameOffset() > 0 {
				erh.Flags.Skip = false
			}
		}

		// don't skip events with related activity ID
		erh.Flags.Skip = erh.EventRec.RelatedActivityID() == nullGUID

		return fakeError
	}

	// we have to declare a func otherwise c.Stop seems to be called
	defer func() { tt.CheckErr(c.Stop()) }()

	tt.CheckErr(c.Start())

	start := time.Now()
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		//for e := range c.Events {
		c.ProcessEvents(func(e *Event) {
			eventCount++

			_, err := json.Marshal(&e)
			tt.CheckErr(err)
			if e.System.Correlation.ActivityID != nullGUIDStr && e.System.Correlation.RelatedActivityID != nullGUIDStr {
				t.Logf("Provider=%s ActivityID=%s RelatedActivityID=%s", e.System.Provider.Name, e.System.Correlation.ActivityID, e.System.Correlation.RelatedActivityID)
			}
			//t.Log(string(b))
		})
	}()

	time.Sleep(10 * time.Second)

	tt.CheckErr(c.Stop())
	wg.Wait()

	// we got many events so some must have been skipped
	t.Logf("skipped %d events", c.Skipped.Load())
	tt.Assert(c.Skipped.Load() == 0)

	delta := time.Since(start)
	eps := float64(eventCount) / delta.Seconds()
	t.Logf("Received: %d events in %s (%d EPS)", eventCount, delta, int(eps))

	tt.ExpectErr(c.LastError(), fakeError)
}

func TestLostEvents(t *testing.T) {

	tt := toast.FromT(t)

	// Producer part
	ses := NewRealTimeSession("GolangTest")
	// small buffer size on purpose to trigger event loss
	ses.properties.BufferSize = 1

	prov, err := ParseProvider("Microsoft-Windows-Kernel-Memory" + ":0xff")
	tt.CheckErr(err)
	// enabling provider
	tt.CheckErr(ses.EnableProvider(prov))
	defer ses.Stop()

	// ! TESTING
	// Set acces for the Eventlog-Security trace (admin is not enough)
	const SecurityLogReadFlags2 = TRACELOG_ACCESS_REALTIME |
		TRACELOG_REGISTER_GUIDS |
		WMIGUID_QUERY |
		WMIGUID_NOTIFICATION
	securityLogGuid := MustParseGUID("54849625-5478-4994-a5ba-3e3b0328c30d")
	tt.CheckErr(AddProviderAccess(*securityLogGuid, "", SecurityLogReadFlags2))
	// EventAccessControl(
	// 	securityLogGuid,
	// 	uint32(EVENT_SECURITY_SET_DACL), // Use SET instead of ADD
	// 	nil,                             // Use current process token
	// 	SecurityLogReadFlags,
	// 	true,
	// )

	// Consumer part
	c := NewConsumer(context.Background()).FromSessions(ses).FromTraceNames(EventlogSecurity)
	// we have to declare a func otherwise c.Stop does not seem to be called
	defer func() { tt.CheckErr(c.Stop()) }()

	// starting consumer
	tt.CheckErr(c.Start())
	cnt := uint64(0)
	go func() {
		//for range c.Events {
		c.ProcessEvents(func(e *Event) {
			cnt++
		})
	}()
	time.Sleep(20 * time.Second)
	tt.CheckErr(c.Stop())
	time.Sleep(5 * time.Second)
	t.Logf("Events received: %d", cnt)
	t.Logf("Events lost: %d", c.LostEvents.Load())

	traceInfo, ok := c.GetTraceCopy("GolangTest")
	if ok {
		t.Logf("[LogFileHeader] Events lost: %d", traceInfo.TraceLogFile.LogfileHeader.GetEventsLost())
		t.Logf("[Trace] RTLostEvents: %d", traceInfo.RTLostEvents)
		t.Logf("[Trace] RTLostBuffer: %d", traceInfo.RTLostBuffer)
		t.Logf("[Trace] RTLostFile: %d", traceInfo.RTLostFile)
	} else {
		t.Error("TraceInfo is nil")
	}
	tt.Assert(c.LostEvents.Load() > 0, "Expected to lose events due to small buffer")

	tt.Assert(c.LostEvents.Load() == traceInfo.RTLostEvents, "Lost events count mismatch")
}

func jsonStr(i interface{}) string {
	var b []byte
	var err error
	if b, err = json.Marshal(i); err != nil {
		panic(err)
	}
	return string(b)
}

func TestConsumerCallbacks(t *testing.T) {
	var prov Provider
	var err error

	eventCount := 0
	tt := toast.FromT(t)

	// Producer part
	ses := NewRealTimeSession("GolangTest")

	prov, err = ParseProvider(KernelFileProviderName + ":0xff:12,13,14,15,16")
	tt.CheckErr(err)
	// enabling provider
	tt.CheckErr(ses.EnableProvider(prov))
	// starting session
	tt.CheckErr(ses.Start())
	// checking session is running (routing events to our session)
	tt.Assert(ses.IsStarted())
	kernelFileProviderChannel := prov.Name + "/Analytic"
	kernelProviderGUID := prov.GUID

	defer ses.Stop()

	// Consumer part
	c := NewConsumer(context.Background()).FromSessions(ses) //.FromTraceNames(EventlogSecurity)

	c.EventRecordHelperCallback = func(erh *EventRecordHelper) (err error) {

		switch erh.EventID() {
		case 12, 14, 15, 16:
			break
		default:
			erh.Skip()
		}

		return
	}

	type file struct {
		name  string
		flags struct {
			read  bool
			write bool
		}
	}

	fileObjectMapping := make(map[string]*file)
	c.EventPreparedCallback = func(h *EventRecordHelper) error {
		tt.Assert(h.Provider() == prov.Name)
		tt.Assert(h.ProviderGUID() == prov.GUID)
		tt.Assert(h.EventRec.EventHeader.ProviderId.Equals(&kernelProviderGUID))
		tt.Assert(h.TraceInfo.ProviderGUID.Equals(&kernelProviderGUID))
		tt.Assert(h.Channel() == kernelFileProviderChannel)

		switch h.EventID() {
		case 12:
			tt.CheckErr(h.ParseProperties("FileName", "FileObject", "CreateOptions"))

			if fo, err := h.GetPropertyString("FileObject"); err == nil {
				if fn, err := h.GetPropertyString("FileName"); err == nil {
					fileObjectMapping[fo] = &file{name: fn}
				}
			}

			coUint, err := h.GetPropertyUint("CreateOptions")
			tt.CheckErr(err)
			coInt, err := h.GetPropertyInt("CreateOptions")
			tt.CheckErr(err)
			tt.Assert(coUint != 0 && coUint == uint64(coInt))

			unk, err := h.GetPropertyString("UnknownProperty")
			tt.Assert(unk == "")
			tt.ExpectErr(err, ErrUnknownProperty)

			// we skip file create events
			h.Skip()

		case 14:
			tt.CheckErr(h.ParseProperties("FileObject"))

			if object, err := h.GetPropertyString("FileObject"); err == nil {
				delete(fileObjectMapping, object)
			}

			// skip file close events
			h.Skip()

		case 15, 16:
			var f *file
			var object string
			var ok bool

			tt.CheckErr(h.ParseProperty("FileObject"))

			if object, err = h.GetPropertyString("FileObject"); err != nil {
				h.Skip()
				break
			}

			foUint, _ := h.GetPropertyUint("FileObject")
			tt.Assert(fmt.Sprintf("0x%X", foUint) == object)

			if f, ok = fileObjectMapping[object]; !ok {
				// we skip events we cannot enrich
				h.Skip()
				break
			}

			if (h.EventID() == 15 && f.flags.read) ||
				(h.EventID() == 16 && f.flags.write) {
				h.Skip()
				break
			}

			h.SetProperty("FileName", f.name)
			f.flags.read = (h.EventID() == 15)
			f.flags.write = (h.EventID() == 16)

			// event volume will so low that this call should have no effect
			h.Skippable()

		default:
			h.Skip()
		}

		return nil
	}

	// we have to declare a func otherwise c.Stop does not seem to be called
	defer func() { tt.CheckErr(c.Stop()) }()

	// starting consumer
	tt.CheckErr(c.Start())

	//testfile := `\Windows\Temp\test.txt`
	testfile := filepath.Join(t.TempDir()[2:], "test.txt")
	// Strip drive letter from testfile (e.g. "E:" -> "")
	t.Logf("testfile: %s", testfile)

	start := time.Now()
	var etwread int
	var etwwrite int

	pid := os.Getpid()
	// consuming events in Golang
	go func() {
		//for e := range c.Events {
		c.ProcessEvents(func(e *Event) {
			eventCount++

			_, err := json.Marshal(&e)
			tt.CheckErr(err)
			switch e.System.EventID {
			case 15, 16:
				var fn string
				var ok bool

				if fn, ok = e.GetPropertyString("FileName"); !ok {
					break
				}

				if !strings.Contains(fn, testfile) {
					break
				}

				if e.System.Execution.ProcessID != uint32(pid) {
					break
				}

				if e.System.EventID == 15 {
					etwread++
				} else {
					etwwrite++
				}
			}
		})
	}()

	// creating test files
	nReadWrite := 0
	//tf := fmt.Sprintf("C:%s", testfile) // error
	tf := testfile
	for ; nReadWrite < randBetween(800, 1000); nReadWrite++ {
		tmp := fmt.Sprintf("%s.%d", tf, nReadWrite)
		tt.CheckErr(os.WriteFile(tmp, []byte("testdata"), 7777))
		_, err = os.ReadFile(tmp)
		tt.CheckErr(err)
		time.Sleep(time.Millisecond)
	}

	d := time.Duration(0)
	sleep := time.Second
	for d < 10*time.Second {
		if etwread == nReadWrite && etwwrite == nReadWrite {
			break
		}
		time.Sleep(sleep)
		d += sleep
	}

	// wait a couple of seconds more to see if we get more events
	time.Sleep(10 * time.Second)

	// stopping consumer
	tt.CheckErr(c.Stop())

	tt.Assert(eventCount != 0, "did not receive any event")
	tt.Assert(c.Skipped.Load() == 0)
	// verifying that we caught all events
	t.Logf("read=%d etwread=%d", nReadWrite, etwread)
	tt.Assert(nReadWrite == etwread)
	t.Logf("write=%d etwwrite=%d", nReadWrite, etwwrite)
	tt.Assert(nReadWrite == etwwrite)

	delta := time.Since(start)
	eps := float64(eventCount) / delta.Seconds()
	t.Logf("Received: %d events in %s (%d EPS)", eventCount, delta, int(eps))

	// checking any consumer error
	tt.CheckErr(c.LastError())
}

func TestParseProvider(t *testing.T) {
	t.Parallel()

	tt := toast.FromT(t)

	if _, err := ParseProvider(KernelFileProviderName); err != nil {
		t.Error(err)
	}

	p, err := ParseProvider(KernelFileProviderName + ":255")
	tt.CheckErr(err)
	tt.Assert(p.EnableLevel == 255)

	p, err = ParseProvider(KernelFileProviderName + ":255:0,1,2,3,4:4242")
	tt.CheckErr(err)
	for i, eventID := range p.Filter {
		tt.Assert(i == int(eventID))
	}

	p, err = ParseProvider(KernelFileProviderName + ":255:1,2,3,4:4242")
	tt.CheckErr(err)
	tt.Assert(p.EnableLevel == 255 && p.MatchAnyKeyword == 4242)

	p, err = ParseProvider(KernelFileProviderName + ":255:1,2,3,4:4242:1337")
	tt.CheckErr(err)
	tt.Assert(p.EnableLevel == 255 && p.MatchAnyKeyword == 4242 && p.MatchAllKeyword == 1337)

	// this calls must panic on error
	MustParseProvider(KernelFileProviderName)
	tt.ShouldPanic(func() { MustParseProvider("Microsoft-Unknown-Provider") })
}

func TestConvertSid(t *testing.T) {
	t.Parallel()

	var sid *SID
	var err error

	tt := toast.FromT(t)
	systemSID := "S-1-5-18"

	sid, err = ConvertStringSidToSidW(systemSID)
	tt.CheckErr(err)
	tt.Log(sid)
}

func TestSessionSlice(t *testing.T) {
	t.Parallel()

	tt := toast.FromT(t)

	intSlice := make([]int, 0)
	sessions := make([]Session, 0)
	for i := 0; i < 10; i++ {
		sessions = append(sessions, NewRealTimeSession(fmt.Sprintf("test-%d", i)))
		intSlice = append(intSlice, i)
	}

	tt.Assert(len(SessionSlice(sessions)) == len(sessions))
	// should panic because parameter is not a slice
	tt.ShouldPanic(func() { SessionSlice(sessions[0]) })
	// should panic because items do not implement Session
	tt.ShouldPanic(func() { SessionSlice(intSlice) })
}

// When TestingGoEtw session buffer fills up due to high event rate from providers
// CloseTrace will not terminate ProcessTrace, the docs don't mention this in detail
// but ProcessTrace will exit only when all remaining events are processed
// (means, that callback has been called an returned from each remaining event)
// bufferCallback returning 0 will NOT cause ProcessTrace to exit inmediately.
// it still has to wait as if CloseTrace was called. (you can debug this to see it)
//
// Since we are using a sleep inside the callback on purpose, ProcessTrace will
// not end, thus the goroutine will not trigger Done() signaling that it ended.
// This will cause c.Wait() to wait for too long, an hour with this test.
// The test will use StopWithTimeout to limit the consumer if after a certain
// amount of time ProcessTrace does not exit after timeout it will terminate
// the goroutine.
// Abort is the same but with no timeout.
func TestCallbackConcurrency(t *testing.T) {
	tt := toast.FromT(t)
	SetDebugLevel(false)

	c := NewConsumer(context.Background())

	c.EventRecordHelperCallback = nil
	c.EventPreparedCallback = nil
	c.EventCallback = nil

	var callCount atomic.Int32
	var concurrent atomic.Bool
	var currentlyExecuting atomic.Int32

	// Replace default callback with test version
	c.EventRecordCallback = func(er *EventRecord) bool {
		callCount.Add(1)

		// If another callback is already executing, we have concurrent execution
		if currentlyExecuting.Add(1) > 1 {
			concurrent.Store(true)
		}
		time.Sleep(100 * time.Millisecond) // Force overlap if concurrent
		currentlyExecuting.Add(-1)
		return true
	}

	s := NewRealTimeSession("TestingGoEtw")
	defer s.Stop()

	// add some potential high volume providers
	providers := []string{
		"Microsoft-Windows-Kernel-Process",
		"Microsoft-Windows-Kernel-File:0xff:12,13,14,15,16",
	}
	for _, p := range providers {
		if err := s.EnableProvider(MustParseProvider(p)); err != nil {
			t.Fatalf("Enable provider error: %v", err)
		}
	}

	// Open multiple traces to force potential concurrent execution
	c.FromSessions(s).
		FromTraceNames("EventLog-System").
		FromTraceNames("EventLog-Application").
		FromTraceNames("Steam Event Tracing")

	tt.CheckErr(c.Start())

	// Wait for some events
	time.Sleep(5 * time.Second)

	t.Logf("Waiting for consumer to stop")
	// Stop consumer before checking results
	done := make(chan struct{})
	go func() {
		tt.CheckErr(c.StopWithTimeout(5 * time.Second))
		//tt.CheckErr(c.Abort())
		//tt.CheckErr(c.Stop())
		c.Wait() // make sure the goroutines are actually ended.
		close(done)
	}()

	//time.Sleep(5 * time.Hour)

	select {
	case <-done:
		// Test passed
	case <-time.After(15 * time.Second):
		t.Fatal("c.Wait() did not return within 15 seconds")
		os.Exit(1)
	}

	// This is useful for debugging etw
	t.Logf("Total callbacks executed: %d", callCount.Load())
	if concurrent.Load() {
		t.Logf("Callbacks executed concurrently")
	}
}

func TestQueryTraceProperties(t *testing.T) {
	tt := toast.FromT(t)

	// PSession part - Create a real-time session
	ses := NewRealTimeSession("TestingGoEtw")

	// Create a query properties object for the global query func.
	gp := NewQueryTraceProperties("TestingGoEtw")
	loggerName, _ := syscall.UTF16PtrFromString("TestingGoEtw")

	// Use file provider which generates reliable events
	prov, err := ParseProvider(KernelFileProviderName + ":0xff:12,13,14,15,16")
	tt.CheckErr(err)

	// Enable provider and start session
	tt.CheckErr(ses.EnableProvider(prov))
	tt.CheckErr(ses.Start())
	defer ses.Stop()

	// Test static properties before starting consumer
	sp, err := ses.QueryTrace()
	tt.CheckErr(err)

	err = QueryTrace(loggerName, gp)
	tt.CheckErr(err)

	// chek if name is set
	namew := gp.GetTraceName()
	name := UTF16PtrToString(namew)
	_ = name

	// Compare non-volatile fields that shouldn't change during session lifetime
	tt.Assert(gp.BufferSize == sp.BufferSize,
		"BufferSize mismatch: %d != %d", gp.BufferSize, sp.BufferSize)
	tt.Assert(gp.MinimumBuffers == sp.MinimumBuffers,
		"MinimumBuffers mismatch: %d != %d", gp.MinimumBuffers, sp.MinimumBuffers)
	tt.Assert(gp.MaximumBuffers == sp.MaximumBuffers,
		"MaximumBuffers mismatch: %d != %d", gp.MaximumBuffers, sp.MaximumBuffers)
	tt.Assert(gp.LogFileMode == sp.LogFileMode,
		"LogFileMode mismatch: %d != %d", gp.LogFileMode, sp.LogFileMode)

	// Consumer part
	c := NewConsumer(context.Background()).FromSessions(ses)
	defer c.Stop()

	tt.CheckErr(c.Start())

	eventsReceived := uint32(0)
	go func() {
		//for range c.Events {
		c.ProcessEvents(func(e *Event) {
			eventsReceived++
		})
	}()

	// Wait for some events to be processed
	time.Sleep(5 * time.Second)

	// Fully Stop the consumer before comparing the trace stats.
	tt.CheckErr(c.Stop())

	// Test 1: RealTimeSession.QueryTrace()
	sp2, err := ses.QueryTrace()
	tt.CheckErr(err)
	t.Logf("Session Query - NumberOfBuffers: %d, BuffersWritten: %d, EventsLost: %d",
		sp2.NumberOfBuffers, sp2.BuffersWritten, sp2.EventsLost)

	// Validate sesProp2 has been updated with real trace data
	tt.Assert(sp2.NumberOfBuffers > 0, "Expected NumberOfBuffers > 0, got %d", sp2.NumberOfBuffers)
	tt.Assert(sp2.BuffersWritten > 0, "Expected BuffersWritten > 0, got %d", sp2.BuffersWritten)

	// Test 2: Global QueryTrace()
	err = QueryTrace(loggerName, gp)
	gp2 := gp
	tt.CheckErr(err)
	t.Logf("Global Query - NumberOfBuffers: %d, BuffersWritten: %d, EventsLost: %d",
		gp2.NumberOfBuffers, gp2.BuffersWritten, gp2.EventsLost)

	// Validate sesProp2 matches gProp2 since they query the same trace
	tt.Assert(gp2.NumberOfBuffers == sp2.NumberOfBuffers,
		"NumberOfBuffers mismatch: %d != %d", gp2.NumberOfBuffers, sp2.NumberOfBuffers)
	tt.Assert(gp2.BuffersWritten == sp2.BuffersWritten,
		"BuffersWritten mismatch: %d != %d", gp2.BuffersWritten, sp2.BuffersWritten)
	tt.Assert(gp2.EventsLost == sp2.EventsLost,
		"EventsLost mismatch: %d != %d", gp2.EventsLost, sp2.EventsLost)

	// // Test error case - non-existent trace
	// _, err = QueryTraceName("NonExistentTrace")
	// tt.Assert(err != nil, "Expected error for non-existent trace")

	// Verify that we received some events
	t.Logf("Events received: %d", eventsReceived)
	tt.Assert(eventsReceived > 0, "Expected to receive some events")
}

func TestAVER(t *testing.T) {
	tt := toast.FromT(t)
	_ = tt

	// PSession part - Create a real-time session
	ses := NewRealTimeSession("TestingGoEtw")
	defer ses.Stop()

	trace := newTrace("non-existent")
	trace.realtime = true

	prop := trace.QueryTrace()
	if prop == nil {
		t.Fail()
	}

}
