// ConnTracker helps track active HTTP connections for graceful shutdown
package channels

import (
	"context"
	"net"
	"net/http"
	"sync"
	"time"
)

// ConnTracker tracks active HTTP connections to enable graceful shutdown
type ConnTracker struct {
	mu       sync.RWMutex
	active   map[uintptr]bool
	nextID   uintptr
	callback func()
}

// NewConnTracker creates a new connection tracker
func NewConnTracker() *ConnTracker {
	return &ConnTracker{
		active: make(map[uintptr]bool),
	}
}

// TrackConn wraps HTTP connections for tracking
func (ct *ConnTracker) TrackConn(conn net.Conn) net.Conn {
	ct.mu.Lock()
	defer ct.mu.Unlock()

	id := ct.nextID
	ct.nextID++
	ct.active[id] = true

	tracked := &TrackedConn{
		Conn: conn,
		id:   id,
		ct:   ct,
	}

	return tracked
}

// HasActiveConns checks if there are any active connections
func (ct *ConnTracker) HasActiveConns() bool {
	ct.mu.RLock()
	defer ct.mu.RUnlock()
	return len(ct.active) > 0
}

// OnShutdown sets a callback to be called when shutdown begins
func (ct *ConnTracker) OnShutdown(fn func()) {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	ct.callback = fn
}

// WaitForConns waits for all tracked connections to close with a timeout
func (ct *ConnTracker) WaitForConns(timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if !ct.HasActiveConns() {
				return nil
			}
		}
	}
}

// TrackedConn wraps a net.Conn and tracks its lifecycle
type TrackedConn struct {
	net.Conn
	id uintptr
	ct *ConnTracker
}

func (tc *TrackedConn) Close() error {
	err := tc.Conn.Close()

	tc.ct.mu.Lock()
	delete(tc.ct.active, tc.id)
	if tc.ct.callback != nil && len(tc.ct.active) == 0 && tc.ct.nextID > 0 {
		tc.ct.callback()
	}
	tc.ct.mu.Unlock()

	return err
}
