package storage

import (
	"path/filepath"
	"testing"
	"time"
)

func newSQLiteStore(t *testing.T, maxTotal, maxPerToken int) Store {
	t.Helper()
	path := filepath.Join(t.TempDir(), "oast.db")
	s, err := NewSQLiteStore(path, maxTotal, maxPerToken, 4096, 512, nil)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// TestSQLiteStore_Suite runs the shared backend suite against SQLiteStore.
func TestSQLiteStore_Suite(t *testing.T) { runStoreSuite(t, newSQLiteStore) }

// TestSQLiteStore_RestartPersistence verifies data survives Close + reopen.
func TestSQLiteStore_RestartPersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "oast.db")

	s1, err := NewSQLiteStore(path, 1000, 100, 4096, 512, nil)
	if err != nil {
		t.Fatalf("open #1: %v", err)
	}
	d := &Domain{Name: "oast.test", ResponseIP: "127.0.0.1"}
	if err := s1.CreateDomain(ctxB(), d); err != nil {
		t.Fatalf("CreateDomain: %v", err)
	}
	tk := &Token{Value: "pers1", DomainID: d.ID, UserID: 1, ExpiresAt: time.Now().Add(time.Hour)}
	if err := s1.CreateToken(ctxB(), tk); err != nil {
		t.Fatalf("CreateToken: %v", err)
	}
	if _, err := s1.AddInteractions(ctxB(), []Interaction{
		{TokenValue: "pers1", Type: InteractionDNS, QName: "pers1.oast.test"},
		{TokenValue: "pers1", Type: InteractionHTTP, Method: "POST", Body: "payload"},
	}); err != nil {
		t.Fatalf("AddInteractions: %v", err)
	}
	if err := s1.Close(); err != nil {
		t.Fatalf("close #1: %v", err)
	}

	s2, err := NewSQLiteStore(path, 1000, 100, 4096, 512, nil)
	if err != nil {
		t.Fatalf("open #2: %v", err)
	}
	t.Cleanup(func() { _ = s2.Close() })

	if _, err := s2.GetDomainByName(ctxB(), "oast.test"); err != nil {
		t.Errorf("domain lost after restart: %v", err)
	}
	got, err := s2.GetTokenByValue(ctxB(), "pers1")
	if err != nil {
		t.Fatalf("token lost after restart: %v", err)
	}
	if got.ID != tk.ID || got.CreatedAt.IsZero() {
		t.Errorf("token roundtrip mismatch: %+v", got)
	}
	items, total, err := s2.ListInteractions(ctxB(), InteractionFilter{TokenValue: "pers1", Limit: 10})
	if err != nil {
		t.Fatalf("ListInteractions after restart: %v", err)
	}
	if total != 2 || len(items) != 2 {
		t.Fatalf("interactions after restart: total=%d items=%d, want 2/2", total, len(items))
	}
	// newest first: the HTTP interaction was inserted last
	if items[0].Type != InteractionHTTP || items[0].Method != "POST" || items[0].Body != "payload" {
		t.Errorf("newest interaction mismatch: %+v", items[0])
	}
	if items[1].QName != "pers1.oast.test" {
		t.Errorf("dns interaction mismatch: %+v", items[1])
	}
}
