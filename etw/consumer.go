//go:build windows
// +build windows

package etw

import (
	"context"
	"fmt"
	"sync"
	"syscall"
)

type Consumer struct {
	sync.WaitGroup
	ctx          context.Context
	cancel       context.CancelFunc
	traceHandles []syscall.Handle
	lastError    error

	Filter EventFilter
	Events chan *Event
}

func NewRealTimeConsumer(ctx context.Context) (c *Consumer) {
	c = &Consumer{
		traceHandles: make([]syscall.Handle, 0, 64),
		Filter:       NewProviderFilter(),
		Events:       make(chan *Event, 4096),
	}
	c.ctx, c.cancel = context.WithCancel(ctx)
	return c
}

func (c *Consumer) InitFilters(providers []Provider) {
	for _, p := range providers {
		c.Filter.FromProvider(&p)
	}
}

func (c *Consumer) bufferCallback(e *EventTraceLogfile) uintptr {
	if c.ctx.Err() != nil {
		// if the consumer has been stopped we
		// don't process event records anymore
		return 0
	}
	// we keep processing event records
	return 1
}

func (c *Consumer) callback(er *EventRecord) uintptr {
	// we get the consumer from user context
	if h, err := NewEventRecordHelper(er); err == nil {
		event := h.BuildEventWithMetadata()
		if c.Filter.Match(event) {
			if err := h.ParseProperties(event); err != nil {
				c.lastError = err
			} else {
				// we have to check again here as the lock introduced delay
				if c.ctx.Err() == nil {
					c.Events <- event
				}
			}
		}
	}
	return 0
}

func (c *Consumer) newRealTimeLogfile() (loggerInfo EventTraceLogfile) {
	// PROCESS_TRACE_MODE_EVENT_RECORD to receive EventRecords (new format)
	// PROCESS_TRACE_MODE_RAW_TIMESTAMP don't convert TimeStamp member of EVENT_HEADER and EVENT_TRACE_HEADER converted to system time
	// PROCESS_TRACE_MODE_REAL_TIME to receive events in real time
	//loggerInfo.SetProcessTraceMode(PROCESS_TRACE_MODE_EVENT_RECORD | PROCESS_TRACE_MODE_RAW_TIMESTAMP | PROCESS_TRACE_MODE_REAL_TIME)
	loggerInfo.SetProcessTraceMode(PROCESS_TRACE_MODE_EVENT_RECORD | PROCESS_TRACE_MODE_REAL_TIME)
	loggerInfo.BufferCallback = syscall.NewCallbackCDecl(c.bufferCallback)
	loggerInfo.Callback = syscall.NewCallbackCDecl(c.callback)
	return
}

func (c *Consumer) Start() {
	for i := range c.traceHandles {
		i := i
		c.Add(1)
		go func() {
			defer c.Done()
			ProcessTrace(&c.traceHandles[i], 1, nil, nil)
		}()
	}
}

func (c *Consumer) OpenTraces(names ...string) (err error) {
	for _, n := range names {
		if err = c.OpenTrace(n); err != nil {
			return fmt.Errorf("failed to open trace %s: %w", n, err)
		}
	}
	return
}

func (c *Consumer) OpenTrace(name string) (err error) {
	var traceHandle syscall.Handle

	loggerInfo := c.newRealTimeLogfile()

	// We use the session name to open the trace
	if loggerInfo.LoggerName, err = syscall.UTF16PtrFromString(name); err != nil {
		return err
	}

	if traceHandle, err = OpenTrace(&loggerInfo); err != nil {
		return err
	}

	c.traceHandles = append(c.traceHandles, syscall.Handle(traceHandle))
	return nil
}

func (c *Consumer) Err() error {
	return c.lastError
}

func (c *Consumer) Close(wait bool) (lastErr error) {
	// closing trace handles
	for _, h := range c.traceHandles {
		// if we don't wait for traces ERROR_CTX_CLOSE_PENDING is a valid error
		if err := CloseTrace(h); err != nil && err != ERROR_CTX_CLOSE_PENDING {
			lastErr = err
		}
	}
	if wait {
		c.Wait()
	}
	close(c.Events)
	return
}

func (c *Consumer) Stop() (err error) {
	// calling context cancel function
	c.cancel()
	return c.Close(true)
}
