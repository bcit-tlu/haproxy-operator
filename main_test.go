package main

import (
	"context"
	"testing"
	"time"
)

// warnDataplaneInsecure must return promptly on context cancellation —
// a leaked goroutine ticking error logs after shutdown would outlive
// main's logger.
func TestWarnDataplaneInsecureStopsOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		warnDataplaneInsecure(ctx)
	}()
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("warnDataplaneInsecure did not return after context cancel")
	}
}
