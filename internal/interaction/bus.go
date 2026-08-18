// Package interaction owns the async event bus that decouples ingestion
// (DNS/HTTP handlers) from the in-memory Store.
package interaction

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/oast/oast/internal/storage"
)

// ErrDropped is returned by Submit when the bus is full and the event was
// discarded to keep the ingestion path non-blocking.
var ErrDropped = errors.New("event dropped: bus full")

// Bus buffers interactions on a channel and flushes them to the Store in
// batches by a worker pool.
type Bus struct {
	ch      chan storage.Interaction
	store   storage.Store
	batch   int
	flush   time.Duration
	log     *slog.Logger
	dropped atomic.Int64
	total   atomic.Int64

	wg     sync.WaitGroup
	cancel context.CancelFunc
	ctx    context.Context
}

// New returns a Bus. Call Start to begin processing.
func New(ctx context.Context, store storage.Store, buffer, workers, batch int, flush time.Duration, log *slog.Logger) *Bus {
	if buffer <= 0 {
		buffer = 4096
	}
	if workers <= 0 {
		workers = 4
	}
	if batch <= 0 {
		batch = 64
	}
	if flush <= 0 {
		flush = 50 * time.Millisecond
	}
	if log == nil {
		log = slog.Default()
	}
	cctx, cancel := context.WithCancel(ctx)
	return &Bus{
		ch:     make(chan storage.Interaction, buffer),
		store:  store,
		batch:  batch,
		flush:  flush,
		log:    log,
		ctx:    cctx,
		cancel: cancel,
	}
}

// Start spawns the worker pool. Returns immediately.
func (b *Bus) Start(workers int) {
	if workers <= 0 {
		workers = 4
	}
	for i := 0; i < workers; i++ {
		b.wg.Add(1)
		go b.worker(i)
	}
}

// Submit pushes an interaction onto the bus without blocking. Returns ErrDropped
// if the buffer is full. Safe to call from DNS/HTTP hot paths.
func (b *Bus) Submit(iv storage.Interaction) error {
	select {
	case b.ch <- iv:
		return nil
	default:
		b.dropped.Add(1)
		return ErrDropped
	}
}

// Dropped returns the count of events discarded due to a full buffer.
func (b *Bus) Dropped() int64 { return b.dropped.Load() }

// Total returns the count of events submitted for processing (queued or stored).
func (b *Bus) Total() int64 { return b.total.Load() }

// Stop signals workers to drain remaining events and exit. Blocks until all
// workers have flushed their in-flight batches or the drain timeout expires.
func (b *Bus) Stop(drain time.Duration) {
	b.cancel()
	close(b.ch)
	done := make(chan struct{})
	go func() {
		b.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(drain):
		b.log.Warn("event bus drain timed out, some events may be lost")
	}
}

func (b *Bus) worker(id int) {
	defer b.wg.Done()
	batch := make([]storage.Interaction, 0, b.batch)
	ticker := time.NewTicker(b.flush)
	defer ticker.Stop()

	flush := func() {
		if len(batch) == 0 {
			return
		}
		n, err := b.store.AddInteractions(b.ctx, batch)
		if err != nil {
			b.log.Error("store.AddInteractions failed",
				"worker", id, "batch", len(batch), "err", err)
		} else {
			b.total.Add(int64(n))
		}
		batch = batch[:0]
	}

	for {
		select {
		case iv, ok := <-b.ch:
			if !ok {
				flush()
				return
			}
			batch = append(batch, iv)
			if len(batch) >= b.batch {
				flush()
			}
		case <-ticker.C:
			flush()
		case <-b.ctx.Done():
			// drain whatever is left without blocking on ticker
			flush()
			for {
				select {
				case iv, ok := <-b.ch:
					if !ok {
						return
					}
					batch = append(batch, iv)
					if len(batch) >= b.batch {
						flush()
					}
				default:
					flush()
					return
				}
			}
		}
	}
}
