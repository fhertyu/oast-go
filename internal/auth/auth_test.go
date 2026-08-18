package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/oast/oast/internal/storage"
)

func TestCan(t *testing.T) {
	if !Can(storage.RoleAdmin, PermManageUsers) {
		t.Error("admin should manage users")
	}
	if !Can(storage.RoleAuditor, PermViewAllInteractions) {
		t.Error("auditor should view all")
	}
	if Can(storage.RoleViewer, PermViewAllInteractions) {
		t.Error("viewer should not view all")
	}
	if Can(storage.RoleViewer, PermManageUsers) {
		t.Error("viewer should not manage users")
	}
}

func TestMissing(t *testing.T) {
	missing := Missing(storage.RoleViewer, PermViewOwnInteractions, PermExportInteractions)
	if len(missing) != 1 || missing[0] != PermExportInteractions {
		t.Errorf("missing = %v", missing)
	}
}

func TestPassword_RoundTrip(t *testing.T) {
	h, err := HashPassword("hunter2", 10)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if err := VerifyPassword(h, "hunter2"); err != nil {
		t.Errorf("verify correct: %v", err)
	}
	if err := VerifyPassword(h, "wrong"); err == nil {
		t.Error("expected wrong password to fail")
	}
}

func TestPassword_CostClamp(t *testing.T) {
	h, err := HashPassword("x", 99) // out of range -> default cost
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if err := VerifyPassword(h, "x"); err != nil {
		t.Errorf("verify: %v", err)
	}
}

func TestJWT_AccessRoundTrip(t *testing.T) {
	j := NewJWT("supersecret-value-1234567890", time.Minute, time.Hour)
	u := &storage.User{ID: 42, Role: storage.RoleAdmin}
	tok, err := j.IssueAccess(u)
	if err != nil {
		t.Fatalf("IssueAccess: %v", err)
	}
	claims, err := j.VerifyAccess(tok)
	if err != nil {
		t.Fatalf("VerifyAccess: %v", err)
	}
	if claims.UserID != 42 || claims.Role != storage.RoleAdmin {
		t.Errorf("claims = %+v", claims)
	}
}

func TestJWT_VerifyRejectsBad(t *testing.T) {
	j := NewJWT("supersecret-value-1234567890", time.Minute, time.Hour)
	if _, err := j.VerifyAccess("not-a-token"); err == nil {
		t.Error("expected error for malformed token")
	}
	// wrong secret
	j2 := NewJWT("a-different-secret-value-1234567", time.Minute, time.Hour)
	tok, _ := j.IssueAccess(&storage.User{ID: 1, Role: storage.RoleViewer})
	if _, err := j2.VerifyAccess(tok); err == nil {
		t.Error("expected signature mismatch error")
	}
}

func TestJWT_RefreshEntropy(t *testing.T) {
	j := NewJWT("supersecret-value-1234567890", time.Minute, time.Hour)
	seen := map[string]bool{}
	for i := 0; i < 1000; i++ {
		rt, err := j.GenerateRefresh()
		if err != nil {
			t.Fatalf("GenerateRefresh: %v", err)
		}
		if len(rt) != 64 {
			t.Errorf("refresh len = %d want 64", len(rt))
		}
		if seen[rt] {
			t.Fatalf("refresh collision at %d", i)
		}
		seen[rt] = true
		h1 := HashRefresh(rt)
		h2 := HashRefresh(rt)
		if h1 != h2 {
			t.Errorf("hash not deterministic")
		}
	}
}

func TestJWT_ExpiredToken(t *testing.T) {
	j := NewJWT("supersecret-value-1234567890", -time.Minute, time.Hour)
	tok, _ := j.IssueAccess(&storage.User{ID: 1, Role: storage.RoleAdmin})
	if _, err := j.VerifyAccess(tok); err == nil {
		t.Error("expected expired error")
	}
}

func TestMiddleware_AuthAndRequire(t *testing.T) {
	j := NewJWT("supersecret-value-1234567890", time.Minute, time.Hour)
	auth := NewAuthenticator(j)

	called := false
	h := auth.Middleware(Require(PermManageUsers)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u := UserFromContext(r.Context())
		if u == nil || u.ID != 42 {
			t.Errorf("user in ctx = %+v", u)
		}
		called = true
	})))

	// valid admin token
	tok, _ := j.IssueAccess(&storage.User{ID: 42, Role: storage.RoleAdmin})
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if !called {
		t.Error("handler not called for admin")
	}

	// viewer lacks PermManageUsers
	called = false
	tok, _ = j.IssueAccess(&storage.User{ID: 1, Role: storage.RoleViewer})
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if called {
		t.Error("handler should not be called for viewer")
	}
	if w.Code != http.StatusForbidden {
		t.Errorf("viewer status = %d want 403", w.Code)
	}

	// missing header
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("no-header status = %d want 401", w.Code)
	}

	// bad token
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer garbage")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("bad-token status = %d want 401", w.Code)
	}
}
