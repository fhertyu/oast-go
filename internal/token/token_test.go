package token

import (
	"context"
	"testing"
	"time"

	"github.com/oast/oast/internal/storage"
)

type fakeStore struct {
	storage.Store
	created   []*storage.Token
	conflictN int // make first N creates conflict
}

func (f *fakeStore) CreateToken(ctx context.Context, t *storage.Token) error {
	if f.conflictN > 0 {
		f.conflictN--
		return storage.ErrConflictT("conflict")
	}
	t.ID = int64(len(f.created) + 1)
	t.CreatedAt = time.Now()
	f.created = append(f.created, t)
	return nil
}
func (f *fakeStore) RevokeToken(ctx context.Context, id int64) error { return nil }
func (f *fakeStore) GetTokenByValue(ctx context.Context, v string) (*storage.Token, error) {
	for _, t := range f.created {
		if t.Value == v {
			cp := *t
			return &cp, nil
		}
	}
	return nil, storage.ErrNotFoundT("token")
}
func (f *fakeStore) MarkExpiredTokens(ctx context.Context, now time.Time) (int, error) {
	n := 0
	for _, t := range f.created {
		if t.Status == storage.TokenActive && now.After(t.ExpiresAt) {
			t.Status = storage.TokenExpired
			n++
		}
	}
	return n, nil
}

func TestMatchToken_DnslogLayout(t *testing.T) {
	fs := &fakeStore{}
	fs.created = append(fs.created, &storage.Token{Value: "xxx", Status: storage.TokenActive})

	cases := []struct {
		prefix     []string
		wantToken  string
		wantData   []string
	}{
		{[]string{"root", "xxx"}, "xxx", []string{"root"}},
		{[]string{"root", "user", "xxx"}, "xxx", []string{"root", "user"}},
		{[]string{"xxx"}, "xxx", nil},
		{[]string{"xxx", "root"}, "xxx", []string{"root"}}, // token first
		{[]string{"data1", "unknown"}, "unknown", []string{"data1"}}, // no registered token -> zone-bordering guess
		{nil, "", nil},
	}
	for i, c := range cases {
		tok, data := MatchToken(context.Background(), fs, c.prefix)
		if tok != c.wantToken {
			t.Errorf("case %d token=%q want %q", i, tok, c.wantToken)
		}
		if len(data) != len(c.wantData) {
			t.Errorf("case %d data=%v want %v", i, data, c.wantData)
			continue
		}
		for j := range data {
			if data[j] != c.wantData[j] {
				t.Errorf("case %d data[%d]=%q want %q", i, j, data[j], c.wantData[j])
			}
		}
	}
}

func TestGenerate_LengthAndCharset(t *testing.T) {
	for i := 0; i < 200; i++ {
		v, err := Generate()
		if err != nil {
			t.Fatalf("Generate: %v", err)
		}
		if err := Validate(v); err != nil {
			t.Errorf("Validate(%q): %v", v, err)
		}
	}
}

func TestGenerate_Uniqueness(t *testing.T) {
	seen := make(map[string]bool, 10000)
	for i := 0; i < 10000; i++ {
		v, err := Generate()
		if err != nil {
			t.Fatalf("Generate: %v", err)
		}
		if seen[v] {
			t.Fatalf("collision at %d: %q", i, v)
		}
		seen[v] = true
	}
}

func TestValidate_RejectsBad(t *testing.T) {
	bad := []string{
		"", "short", "toolongtokenvalue", "1234567890123456",
		"ABCDEFGHIJKLMNOP", // uppercase + I/L/O
	}
	for _, b := range bad {
		if err := Validate(b); err == nil {
			t.Errorf("Validate(%q) expected error", b)
		}
	}
}

func TestManager_Create_RetryOnCollision(t *testing.T) {
	fs := &fakeStore{conflictN: 3}
	m := NewManager(fs, time.Hour)
	tk, err := m.Create(context.Background(), CreateRequest{UserID: 1, ProjectID: 1, DomainID: 1})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if tk.Value == "" {
		t.Fatal("empty value")
	}
	if len(fs.created) != 1 {
		t.Errorf("created count = %d, want 1 (after retries)", len(fs.created))
	}
}

func TestManager_Create_AllCollide(t *testing.T) {
	fs := &fakeStore{conflictN: 99}
	m := NewManager(fs, time.Hour)
	_, err := m.Create(context.Background(), CreateRequest{UserID: 1, ProjectID: 1, DomainID: 1})
	if err == nil {
		t.Fatal("expected error after exhausting retries")
	}
}

func TestManager_Create_Validation(t *testing.T) {
	m := NewManager(&fakeStore{}, time.Hour)
	cases := []CreateRequest{
		{ProjectID: 1, DomainID: 1},        // no user
		{UserID: 1, DomainID: 1},          // no project
		{UserID: 1, ProjectID: 1},          // no domain
	}
	for i, c := range cases {
		if _, err := m.Create(context.Background(), c); err == nil {
			t.Errorf("case %d expected validation error", i)
		}
	}
}

func TestManager_SweepExpired(t *testing.T) {
	fs := &fakeStore{}
	m := NewManager(fs, time.Hour)
	past := time.Now().Add(-time.Hour)
	tk := &storage.Token{
		Value: "expiredtoken123", DomainID: 1, UserID: 1, ProjectID: 1,
		Status: storage.TokenActive, ExpiresAt: past,
	}
	fs.created = append(fs.created, tk)
	n, err := m.SweepExpired(context.Background())
	if err != nil {
		t.Fatalf("SweepExpired: %v", err)
	}
	if n != 1 {
		t.Errorf("swept = %d want 1", n)
	}
	if tk.Status != storage.TokenExpired {
		t.Errorf("status = %s want expired", tk.Status)
	}
}
