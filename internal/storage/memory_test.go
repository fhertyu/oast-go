package storage

import "testing"

func newMemoryStore(t *testing.T, maxTotal, maxPerToken int) Store {
	t.Helper()
	return NewMemoryStore(maxTotal, maxPerToken, 4096)
}

// TestMemoryStore_Suite runs the shared backend suite against MemoryStore.
func TestMemoryStore_Suite(t *testing.T) { runStoreSuite(t, newMemoryStore) }
