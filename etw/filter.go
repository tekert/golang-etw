//go:build windows

package etw

import (
	"sync"

	"github.com/0xrawsec/golang-utils/datastructs"
)

type IEvent interface {
	ProviderGUID() GUID
	EventID() uint16
}

// EventFilter interface to filter events based on a given
// definition
type EventFilter interface {
	// Match must return true if the event has to be filtered in
	Match(IEvent) bool
	// Update adds a filter for/from a given provider
	Update(p *Provider)
}

type baseFilter struct {
	sync.RWMutex
	m map[GUID]*datastructs.Set
}

// matchKey checks if the event matches the filter based on the key
// provided
func (f *baseFilter) matchKey(key GUID, e IEvent) bool {
	f.RLock()
	defer f.RUnlock()

	// map is nil
	if f.m == nil {
		return true
	}

	// Filter is empty
	if len(f.m) == 0 {
		return true
	}

	if eventids, ok := f.m[key]; ok {
		if eventids.Len() > 0 {
			return eventids.Contains(e.EventID())
		}
		return true
	}
	// we return true if no filter is found
	return true
}

// ProviderFilter structure to filter events based on Provider
// definition
type ProviderFilter struct {
	baseFilter
}

// NewProviderFilter creates a new ProviderFilter structure
func NewProviderFilter() *ProviderFilter {
	f := ProviderFilter{}
	f.m = make(map[GUID]*datastructs.Set)
	return &f
}


// Match checks if an event matches the provider filter by comparing the event's provider GUID
// against the filter's key.
func (f *ProviderFilter) Match(e IEvent) bool {
	return f.matchKey(e.ProviderGUID(), e)
}

// Update adds a filter for/from a given provider
func (f *ProviderFilter) Update(p *Provider) {
	f.Lock()
	defer f.Unlock()
	if len(p.Filter) > 0 {
		s := datastructs.ToInterfaceSlice(p.Filter)
		f.m[p.GUID] = datastructs.NewInitSet(s...)
	}
}
