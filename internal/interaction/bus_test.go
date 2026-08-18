package interaction

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/oast/oast/internal/storage"
)

type countingStore struct {
	storage.Store
	mu     sync.Mutex
	stored []storage.Interaction
}

func (c *countingStore) AddInteractions(ctx context.Context, batch []storage.Interaction) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.stored = append(c.stored, batch...)
	return len(batch), nil
}

func TestBus_Flushes(t *testing.T) {
	cs := &countingStore{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	bus := New(ctx, cs, 64, 2, 4, 5*time.Millisecond, slog.Default())
	bus.Start(2)

	for i := 0; i < 20; i++ {
		if err := bus.Submit(storage.Interaction{TokenValue: "tk", Type: storage.InteractionDNS, SrcIP: "1.1.1.1"}); err != nil {
			t.Fatalf("Submit: %v", err)
		}
	}

	deadline := time.After(1 * time.Second)
	for {
		cs.mu.Lock()
		n := len(cs.stored)
		cs.mu.Unlock()
		if n >= 20 {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("only %d stored, want 20", n)
		case <-time.After(5 * time.Millisecond):
		}
	}

	bus.Stop(500 * time.Millisecond)
	cs.mu.Lock()
	defer cs.mu.Unlock()
	if len(cs.stored) != 20 {
		t.Errorf("stored = %d want 20", len(cs.stored))
	}
	if bus.Total() != 20 {
		t.Errorf("total = %d want 20", bus.Total())
	}
}

func TestBus_DropsWhenFull(t *testing.T) {
	cs := &countingStore{}
	// never-drains store: AddInteractions blocks long enough to fill the bus
	bus := New(context.Background(), cs, 2, 1, 100, time.Hour, slog.Default())
	// don't start workers so the channel fills

	var ok, dropped int64
	for i := 0; i < 100; i++ {
		if err := bus.Submit(storage.Interaction{TokenValue: "tk", Type: storage.InteractionDNS}); err == nil {
			atomic.AddInt64(&ok, 1)
		} else {
			atomic.AddInt64(&dropped, 1)
		}
	}
	if ok != 2 {
		t.Errorf("queued = %d want 2", ok)
	}
	if dropped != 98 {
		t.Errorf("dropped = %d want 98", dropped)
	}
	if bus.Dropped() != 98 {
		t.Errorf("bus.Dropped() = %d want 98", bus.Dropped())
	}
}

func TestBus_StopDrains(t *testing.T) {
	cs := &countingStore{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	bus := New(ctx, cs, 64, 1, 1000, time.Hour, slog.Default())
	bus.Start(1)

	for i := 0; i < 50; i++ {
		bus.Submit(storage.Interaction{TokenValue: "tk", Type: storage.InteractionDNS})
	}
	// wait a moment for the worker to be mid-batch, then stop
	time.Sleep(10 * time.Millisecond)
	bus.Stop(500 * time.Millisecond)

	cs.mu.Lock()
	defer cs.mu.Unlock()
	if len(cs.stored) != 50 {
		t.Errorf("after Stop stored = %d want 50", len(cs.stored))
	}
}

func TestBus_RespectsContextCancel(t *testing.T) {
	cs := &countingStore{}
	ctx, cancel := context.WithCancel(context.Background())
	bus := New(ctx, cs, 64, 2, 4, 5*time.Millisecond, slog.Default())
	bus.Start(2)

	for i := 0; i < 5; i++ {
		bus.Submit(storage.Interaction{TokenValue: "tk", Type: storage.InteractionDNS})
	}
	cancel()
	bus.Stop(500 * time.Millisecond)
	// workers should exit cleanly
}

func TestBus_Defaults(t *testing.T) {
	cs := &countingStore{}
	bus := New(context.Background(), cs, 0, 0, 0, 0, nil)
	if cap(bus.ch) != 4096 {
		t.Errorf("default buffer = %d want 4096", cap(bus.ch))
	}
	if bus.batch != 64 {
		t.Errorf("default batch = %d want 64", bus.batch)
	}
	if bus.flush != 50*time.Millisecond {
		t.Errorf("default flush = %v", bus.flush)
	}
}
