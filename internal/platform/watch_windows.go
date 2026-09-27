package platform

import (
	"context"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Callback slots cannot be freed, so one callback fans out to all watchers.
var (
	watchMu       sync.Mutex
	watchers      = make(map[chan struct{}]bool)
	watchOnce     sync.Once
	watchCallback uintptr
)

func notifyWatchers(_, _, _ uintptr) uintptr {
	watchMu.Lock()
	defer watchMu.Unlock()
	for ch := range watchers {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
	return 0
}

// WatchTopology signals, coalesced, after IP Helper reports a route, unicast
// address or interface change. The channel closes when ctx ends; callers keep
// polling as the fallback.
func WatchTopology(ctx context.Context) (<-chan struct{}, error) {
	watchOnce.Do(func() { watchCallback = windows.NewCallback(notifyWatchers) })
	ch := make(chan struct{}, 1)
	watchMu.Lock()
	watchers[ch] = true
	watchMu.Unlock()
	var handles []windows.Handle
	cancel := func() {
		// CancelMibChangeNotify2 waits for running callbacks to return.
		for _, h := range handles {
			windows.CancelMibChangeNotify2(h)
		}
		watchMu.Lock()
		delete(watchers, ch)
		watchMu.Unlock()
		close(ch)
	}
	for _, register := range []func(uint16, uintptr, unsafe.Pointer, bool, *windows.Handle) error{windows.NotifyRouteChange2, windows.NotifyUnicastIpAddressChange, windows.NotifyIpInterfaceChange} {
		var h windows.Handle
		if err := register(windows.AF_UNSPEC, watchCallback, nil, false, &h); err != nil {
			cancel()
			return nil, err
		}
		handles = append(handles, h)
	}
	go func() {
		<-ctx.Done()
		cancel()
	}()
	return ch, nil
}
