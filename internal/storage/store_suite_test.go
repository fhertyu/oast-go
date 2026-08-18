package storage

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

// storeFactory builds a Store with the given capacity knobs. The shared suite
// runs against every backend so memory and sqlite stay behaviorally identical.
type storeFactory func(t *testing.T, maxTotal, maxPerToken int) Store

// runStoreSuite exercises the full Store contract (eviction, caps, TTL
// cleanup, filters, pagination, truncation, stats, purge) on any backend.
func runStoreSuite(t *testing.T, mk storeFactory) {
	t.Helper()

	t.Run("UserCRUD", func(t *testing.T) {
		s := mk(t, 100, 10)
		u := mustUser(t, s, "alice")
		if u.ID == 0 || u.CreatedAt.IsZero() {
			t.Fatal("id/created_at not set")
		}
		if err := s.CreateUser(ctxB(), &User{Username: "alice"}); err == nil {
			t.Fatal("expected duplicate-username conflict")
		}
		got, err := s.GetUserByUsername(ctxB(), "alice")
		if err != nil {
			t.Fatalf("GetUserByUsername: %v", err)
		}
		if got.ID != u.ID {
			t.Errorf("id mismatch")
		}
		u.Role = RoleAuditor
		if err := s.UpdateUser(ctxB(), u); err != nil {
			t.Fatalf("UpdateUser: %v", err)
		}
		got, _ = s.GetUserByUsername(ctxB(), "alice")
		if got.Role != RoleAuditor {
			t.Errorf("role not updated")
		}
	})

	t.Run("AddInteractions_AndFilter", func(t *testing.T) {
		s := mk(t, 100, 10)
		d := mustDomain(t, s, "oast.test")
		u := mustUser(t, s, "alice")
		p := mustProject(t, s, u.ID)
		mustToken(t, s, "tokA", d.ID, u.ID, p.ID)
		mustToken(t, s, "tokB", d.ID, u.ID, p.ID)

		batch := []Interaction{
			{TokenValue: "tokA", DomainID: d.ID, Type: InteractionDNS, QName: "tokA.oast.test", QType: "A", SrcIP: "1.1.1.1"},
			{TokenValue: "tokA", DomainID: d.ID, Type: InteractionHTTP, Method: "GET", SrcIP: "1.1.1.1"},
			{TokenValue: "tokB", DomainID: d.ID, Type: InteractionDNS, QName: "tokB.oast.test", QType: "TXT", SrcIP: "2.2.2.2"},
		}
		n, err := s.AddInteractions(ctxB(), batch)
		if err != nil {
			t.Fatalf("AddInteractions: %v", err)
		}
		if n != 3 {
			t.Errorf("stored = %d, want 3", n)
		}

		// filter by token
		items, total, err := s.ListInteractions(ctxB(), InteractionFilter{TokenValue: "tokA", Limit: 10})
		if err != nil {
			t.Fatalf("ListInteractions: %v", err)
		}
		if total != 2 || len(items) != 2 {
			t.Errorf("tokA total=%d items=%d, want 2/2", total, len(items))
		}
		// newest first
		if items[0].Type != InteractionHTTP {
			t.Errorf("expected http first, got %s", items[0].Type)
		}

		// filter by type
		_, dnsTotal, _ := s.ListInteractions(ctxB(), InteractionFilter{Type: InteractionDNS, Limit: 10})
		if dnsTotal != 2 {
			t.Errorf("dns total = %d, want 2", dnsTotal)
		}
		// filter by src_ip
		_, ipTotal, _ := s.ListInteractions(ctxB(), InteractionFilter{SrcIP: "1.1.1.1", Limit: 10})
		if ipTotal != 2 {
			t.Errorf("ip total = %d, want 2", ipTotal)
		}

		// ownership scope (TokenValues): only the listed tokens are visible
		items, total, err = s.ListInteractions(ctxB(), InteractionFilter{TokenValues: []string{"tokA"}, Limit: 10})
		if err != nil {
			t.Fatalf("ListInteractions TokenValues: %v", err)
		}
		if total != 2 || len(items) != 2 {
			t.Errorf("tokA scoped total=%d items=%d, want 2/2", total, len(items))
		}
		_, otherTotal, _ := s.ListInteractions(ctxB(), InteractionFilter{TokenValues: []string{"nobody"}, Limit: 10})
		if otherTotal != 0 {
			t.Errorf("unknown token scope total = %d, want 0", otherTotal)
		}
		// combine single-token filter within an ownership set
		_, mixedTotal, _ := s.ListInteractions(ctxB(),
			InteractionFilter{TokenValues: []string{"tokA", "tokB"}, TokenValue: "tokA", Limit: 10})
		if mixedTotal != 2 {
			t.Errorf("mixed scoped total = %d, want 2", mixedTotal)
		}

		// count by token
		c, _ := s.CountInteractionsByToken(ctxB(), "tokA")
		if c != 2 {
			t.Errorf("count tokA = %d, want 2", c)
		}
	})

	t.Run("GlobalFIFOEviction", func(t *testing.T) {
		s := mk(t, 5, 100)
		d := mustDomain(t, s, "oast.test")
		u := mustUser(t, s, "alice")
		p := mustProject(t, s, u.ID)
		mustToken(t, s, "tokX", d.ID, u.ID, p.ID)

		for i := 0; i < 8; i++ {
			_, err := s.AddInteractions(ctxB(), []Interaction{
				{TokenValue: "tokX", DomainID: d.ID, Type: InteractionDNS, SrcIP: "1.1.1.1"},
			})
			if err != nil {
				t.Fatalf("AddInteractions %d: %v", i, err)
			}
		}
		st, _ := s.Stats(ctxB())
		if st.Interactions != 5 {
			t.Errorf("after overflow interactions=%d, want 5 (FIFO)", st.Interactions)
		}
		// index must be consistent with primary store
		c, _ := s.CountInteractionsByToken(ctxB(), "tokX")
		if c != 5 {
			t.Errorf("index count=%d, want 5", c)
		}
	})

	t.Run("PerTokenCap", func(t *testing.T) {
		s := mk(t, 1000, 3)
		d := mustDomain(t, s, "oast.test")
		u := mustUser(t, s, "alice")
		p := mustProject(t, s, u.ID)
		mustToken(t, s, "tokC", d.ID, u.ID, p.ID)

		for i := 0; i < 5; i++ {
			_, _ = s.AddInteractions(ctxB(), []Interaction{
				{TokenValue: "tokC", DomainID: d.ID, Type: InteractionDNS, SrcIP: "1.1.1.1"},
			})
		}
		c, _ := s.CountInteractionsByToken(ctxB(), "tokC")
		if c != 3 {
			t.Errorf("per-token cap count=%d, want 3", c)
		}
		st, _ := s.Stats(ctxB())
		// global stays under 1000; per-token cap evicted 2
		if st.Interactions != 3 {
			t.Errorf("global interactions=%d, want 3", st.Interactions)
		}
	})

	t.Run("Pagination", func(t *testing.T) {
		s := mk(t, 1000, 100)
		d := mustDomain(t, s, "oast.test")
		u := mustUser(t, s, "alice")
		p := mustProject(t, s, u.ID)
		mustToken(t, s, "tokP", d.ID, u.ID, p.ID)

		var batch []Interaction
		for i := 0; i < 25; i++ {
			batch = append(batch, Interaction{TokenValue: "tokP", DomainID: d.ID, Type: InteractionDNS, SrcIP: "1.1.1.1"})
		}
		_, _ = s.AddInteractions(ctxB(), batch)

		page1, total, _ := s.ListInteractions(ctxB(), InteractionFilter{TokenValue: "tokP", Limit: 10, Offset: 0})
		page2, _, _ := s.ListInteractions(ctxB(), InteractionFilter{TokenValue: "tokP", Limit: 10, Offset: 10})

		if total != 25 {
			t.Errorf("total=%d want 25", total)
		}
		if len(page1) != 10 || len(page2) != 10 {
			t.Errorf("page sizes %d/%d", len(page1), len(page2))
		}
		// page1 should be newer than page2
		if page1[0].CreatedAt.Before(page2[0].CreatedAt) {
			t.Errorf("expected page1 newer than page2")
		}
		// no overlap
		if page1[0].ID == page2[0].ID {
			t.Errorf("pages overlap")
		}
	})

	t.Run("BodyTruncation", func(t *testing.T) {
		s := mk(t, 100, 10)
		d := mustDomain(t, s, "oast.test")
		mustToken(t, s, "tokT", d.ID, 1, 0)
		_, err := s.AddInteractions(ctxB(), []Interaction{
			{TokenValue: "tokT", Type: InteractionHTTP, Body: strings.Repeat("A", 4096+512)},
		})
		if err != nil {
			t.Fatalf("AddInteractions: %v", err)
		}
		items, _, _ := s.ListInteractions(ctxB(), InteractionFilter{TokenValue: "tokT", Limit: 1})
		if len(items) != 1 {
			t.Fatalf("items=%d", len(items))
		}
		if len(items[0].Body) > 4096 {
			t.Errorf("body len=%d, want <=4096 after truncation", len(items[0].Body))
		}
	})

	t.Run("RetentionTTL", func(t *testing.T) {
		s := mk(t, 100, 10)
		d := mustDomain(t, s, "oast.test")
		mustToken(t, s, "tokR", d.ID, 1, 0)
		now := time.Now().UTC()
		_, err := s.AddInteractions(ctxB(), []Interaction{
			{TokenValue: "tokR", Type: InteractionDNS, CreatedAt: now.Add(-25 * time.Hour)}, // older than 12h
			{TokenValue: "tokR", Type: InteractionDNS, CreatedAt: now.Add(-5 * time.Hour)},  // newer
		})
		if err != nil {
			t.Fatalf("AddInteractions: %v", err)
		}
		n, err := s.DeleteOldInteractions(ctxB(), now.Add(-12*time.Hour))
		if err != nil {
			t.Fatalf("DeleteOldInteractions: %v", err)
		}
		if n != 1 {
			t.Errorf("deleted=%d, want 1", n)
		}
		_, total, _ := s.ListInteractions(ctxB(), InteractionFilter{TokenValue: "tokR", Limit: 10})
		if total != 1 {
			t.Errorf("remaining=%d, want 1", total)
		}
	})

	t.Run("TokenLifecycle", func(t *testing.T) {
		s := mk(t, 100, 10)
		d := mustDomain(t, s, "oast.test")
		u := mustUser(t, s, "alice")
		p := mustProject(t, s, u.ID)
		tk := mustToken(t, s, "tokL", d.ID, u.ID, p.ID)

		// expired
		past := time.Now().Add(-time.Hour)
		tk2 := &Token{Value: "tokExp", DomainID: d.ID, UserID: u.ID, ProjectID: p.ID, ExpiresAt: past}
		s.CreateToken(ctxB(), tk2)

		n, _ := s.MarkExpiredTokens(ctxB(), time.Now())
		if n != 1 {
			t.Errorf("expired=%d want 1", n)
		}
		got, _ := s.GetTokenByValue(ctxB(), "tokExp")
		if got.Status != TokenExpired {
			t.Errorf("status=%s want expired", got.Status)
		}

		// revoke
		s.RevokeToken(ctxB(), tk.ID)
		got, _ = s.GetToken(ctxB(), tk.ID)
		if got.Status != TokenRevoked || got.RevokedAt == nil {
			t.Errorf("revoke failed")
		}
	})

	t.Run("TokenPurge_InteractionsSurvive", func(t *testing.T) {
		s := mk(t, 100, 10)
		d := mustDomain(t, s, "oast.test")
		u := mustUser(t, s, "alice")
		p := mustProject(t, s, u.ID)
		now := time.Now().UTC()
		tk := &Token{Value: "tokPurge", DomainID: d.ID, UserID: u.ID, ProjectID: p.ID, ExpiresAt: now.Add(-2 * time.Hour)}
		if err := s.CreateToken(ctxB(), tk); err != nil {
			t.Fatalf("CreateToken: %v", err)
		}
		if _, err := s.AddInteractions(ctxB(), []Interaction{
			{TokenValue: "tokPurge", Type: InteractionDNS, CreatedAt: now.Add(-2 * time.Hour)},
		}); err != nil {
			t.Fatalf("AddInteractions: %v", err)
		}
		if _, err := s.MarkExpiredTokens(ctxB(), now); err != nil {
			t.Fatalf("MarkExpiredTokens: %v", err)
		}
		// grace 1h: token expired 2h ago → past grace → hard-deleted
		n, err := s.DeletePurgedTokens(ctxB(), now, time.Hour)
		if err != nil {
			t.Fatalf("DeletePurgedTokens: %v", err)
		}
		if n != 1 {
			t.Fatalf("purged=%d, want 1", n)
		}
		if _, err := s.GetTokenByValue(ctxB(), "tokPurge"); !AsNotFound(err) {
			t.Fatalf("expected not-found after purge, got %v", err)
		}
		// interactions keep the denormalized TokenValue and survive
		c, _ := s.CountInteractionsByToken(ctxB(), "tokPurge")
		if c != 1 {
			t.Errorf("interactions after purge=%d, want 1", c)
		}
	})

	t.Run("VisitorStatsByTokens", func(t *testing.T) {
		s := mk(t, 100, 10)
		d := mustDomain(t, s, "oast.test")
		u := mustUser(t, s, "alice")
		p := mustProject(t, s, u.ID)
		mustToken(t, s, "tokS1", d.ID, u.ID, p.ID)
		mustToken(t, s, "tokS2", d.ID, u.ID, p.ID)

		_, _ = s.AddInteractions(ctxB(), []Interaction{
			{TokenValue: "tokS1", Type: InteractionDNS},
			{TokenValue: "tokS1", Type: InteractionHTTP},
			{TokenValue: "tokS2", Type: InteractionDNS},
		})
		st, err := s.InteractionStatsByTokens(ctxB(), []string{"tokS1"})
		if err != nil {
			t.Fatalf("InteractionStatsByTokens: %v", err)
		}
		if st.Interactions != 2 || st.DNSEvents != 1 || st.HTTPEvents != 1 {
			t.Errorf("tokS1 stats = %+v", st)
		}
		if len(st.Recent) != 2 {
			t.Errorf("recent=%d, want 2", len(st.Recent))
		}
		// empty set must be fail-closed (0), never global
		st, _ = s.InteractionStatsByTokens(ctxB(), []string{})
		if st.Interactions != 0 {
			t.Errorf("empty scope interactions=%d, want 0", st.Interactions)
		}
		st, _ = s.InteractionStatsByTokens(ctxB(), []string{"tokS1", "tokS2"})
		if st.Interactions != 3 {
			t.Errorf("combined scope interactions=%d, want 3", st.Interactions)
		}
	})

	t.Run("RefreshToken", func(t *testing.T) {
		s := mk(t, 100, 10)
		u := mustUser(t, s, "alice")
		rt := &RefreshToken{UserID: u.ID, TokenHash: "hash1", ExpiresAt: time.Now().Add(time.Hour)}
		if err := s.CreateRefreshToken(ctxB(), rt); err != nil {
			t.Fatalf("CreateRefreshToken: %v", err)
		}
		if err := s.CreateRefreshToken(ctxB(), &RefreshToken{TokenHash: "hash1"}); err == nil {
			t.Fatal("expected duplicate-hash conflict")
		}
		got, _ := s.GetRefreshTokenByHash(ctxB(), "hash1")
		if got.ID != rt.ID {
			t.Errorf("id mismatch")
		}
		s.RevokeRefreshToken(ctxB(), rt.ID)
		got, _ = s.GetRefreshTokenByHash(ctxB(), "hash1")
		if got.RevokedAt == nil {
			t.Errorf("revoked_at nil")
		}
		// expired cleanup
		rt2 := &RefreshToken{UserID: u.ID, TokenHash: "hash2", ExpiresAt: time.Now().Add(-time.Hour)}
		s.CreateRefreshToken(ctxB(), rt2)
		n, _ := s.DeleteExpiredRefreshTokens(ctxB(), time.Now())
		if n == 0 {
			t.Errorf("expected expired refresh tokens deleted")
		}
	})

	t.Run("DeleteInteraction_IndexConsistency", func(t *testing.T) {
		s := mk(t, 100, 10)
		d := mustDomain(t, s, "oast.test")
		u := mustUser(t, s, "alice")
		p := mustProject(t, s, u.ID)
		mustToken(t, s, "tokD", d.ID, u.ID, p.ID)

		var batch []Interaction
		for i := 0; i < 3; i++ {
			batch = append(batch, Interaction{TokenValue: "tokD", DomainID: d.ID, Type: InteractionDNS})
		}
		s.AddInteractions(ctxB(), batch)
		items, _, _ := s.ListInteractions(ctxB(), InteractionFilter{TokenValue: "tokD", Limit: 10})
		if len(items) != 3 {
			t.Fatalf("pre-delete len=%d", len(items))
		}
		// delete the middle one
		mid := items[1].ID
		if err := s.DeleteInteraction(ctxB(), mid); err != nil {
			t.Fatalf("DeleteInteraction: %v", err)
		}
		items, total, _ := s.ListInteractions(ctxB(), InteractionFilter{TokenValue: "tokD", Limit: 10})
		if total != 2 {
			t.Errorf("post-delete total=%d want 2", total)
		}
		c, _ := s.CountInteractionsByToken(ctxB(), "tokD")
		if c != 2 {
			t.Errorf("post-delete count=%d want 2", c)
		}
	})

	t.Run("Stats", func(t *testing.T) {
		s := mk(t, 100, 10)
		mustUser(t, s, "alice")
		mustDomain(t, s, "oast.test")
		st, err := s.Stats(ctxB())
		if err != nil {
			t.Fatalf("Stats: %v", err)
		}
		if st.Users != 1 || st.Domains != 1 {
			t.Errorf("stats users=%d domains=%d", st.Users, st.Domains)
		}
	})
}

// ---- suite helpers (interface-level, backend-agnostic) ----

func ctxB() context.Context { return context.Background() }

func mustDomain(t *testing.T, s Store, name string) *Domain {
	t.Helper()
	d := &Domain{Name: name, ResponseIP: "127.0.0.1"}
	if err := s.CreateDomain(ctxB(), d); err != nil {
		t.Fatalf("CreateDomain: %v", err)
	}
	return d
}

func mustUser(t *testing.T, s Store, name string) *User {
	t.Helper()
	u := &User{Username: name, Role: RoleAdmin}
	if err := s.CreateUser(ctxB(), u); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	return u
}

func mustProject(t *testing.T, s Store, owner int64) *Project {
	t.Helper()
	p := &Project{Name: fmt.Sprintf("proj-%d", owner), OwnerID: owner}
	if err := s.CreateProject(ctxB(), p); err != nil {
		t.Fatalf("CreateProject: %v", err)
	}
	return p
}

func mustToken(t *testing.T, s Store, val string, dom, user, proj int64) *Token {
	t.Helper()
	tk := &Token{Value: val, DomainID: dom, UserID: user, ProjectID: proj, ExpiresAt: time.Now().Add(time.Hour)}
	if err := s.CreateToken(ctxB(), tk); err != nil {
		t.Fatalf("CreateToken: %v", err)
	}
	return tk
}
