package domain

import (
	"testing"

	"github.com/oast/oast/internal/storage"
)

func mustDom(t *testing.T, m *Manager, name string) *storage.Domain {
	t.Helper()
	d := &storage.Domain{Name: name, ResponseIP: "1.2.3.4"}
	m.Add(d)
	return d
}

func TestResolve_Basic(t *testing.T) {
	m := NewManager()
	d := mustDom(t, m, "oast.example.com")

	cases := []struct {
		host   string
		wantOK bool
		prefix []string
		dom    *storage.Domain
	}{
		{"a1b2.oast.example.com", true, []string{"a1b2"}, d},
		{"OAST.example.com", true, nil, d},         // host == domain, case-insensitive
		{"x.y.oast.example.com", true, []string{"x", "y"}, d}, // multi-label prefix, data + token
		{"random.example.com", false, nil, nil},
		{"example.com", false, nil, nil},
		{"", false, nil, nil},
	}
	for _, c := range cases {
		dom, prefix, ok := m.Resolve(c.host)
		if ok != c.wantOK {
			t.Errorf("Resolve(%q) ok=%v want %v", c.host, ok, c.wantOK)
			continue
		}
		if !ok {
			continue
		}
		if dom != c.dom {
			t.Errorf("Resolve(%q) dom=%v want %v", c.host, dom, c.dom)
		}
		if len(prefix) != len(c.prefix) {
			t.Errorf("Resolve(%q) prefix=%v want %v", c.host, prefix, c.prefix)
		}
		for i := range prefix {
			if i >= len(c.prefix) || prefix[i] != c.prefix[i] {
				t.Errorf("Resolve(%q) prefix=%v want %v", c.host, prefix, c.prefix)
				break
			}
		}
	}
}

func TestResolve_MultipleDomains_LongestSuffix(t *testing.T) {
	m := NewManager()
	d1 := mustDom(t, m, "oast.example.com")
	d2 := mustDom(t, m, "oast.sec.net")
	// nested: a sub-zone of an existing domain
	d3 := mustDom(t, m, "lab.oast.example.com")

	cases := []struct {
		host string
		dom  *storage.Domain
	}{
		{"tok1.oast.example.com", d1},
		{"tok2.oast.sec.net", d2},
		{"tok3.lab.oast.example.com", d3},         // longest match wins
		{"tok4.oast.example.com", d1},               // d1, not d3
	}
	for _, c := range cases {
		dom, _, ok := m.Resolve(c.host)
		if !ok {
			t.Errorf("Resolve(%q) ok=false", c.host)
			continue
		}
		if dom != c.dom {
			t.Errorf("Resolve(%q) dom=%q want %q", c.host, dom.Name, c.dom.Name)
		}
	}
}

func TestResolve_TrailingDot(t *testing.T) {
	m := NewManager()
	d := mustDom(t, m, "oast.example.com")
	dom, prefix, ok := m.Resolve("a1b2.oast.example.com.")
	if !ok || dom != d || len(prefix) != 1 || prefix[0] != "a1b2" {
		t.Errorf("trailing-dot: ok=%v dom=%v prefix=%v", ok, dom, prefix)
	}
}

func TestGet_All(t *testing.T) {
	m := NewManager()
	mustDom(t, m, "oast.example.com")
	mustDom(t, m, "oast.sec.net")
	if d, ok := m.Get("OAST.example.com"); !ok || d == nil {
		t.Error("Get case-insensitive failed")
	}
	if _, ok := m.Get("nope.com"); ok {
		t.Error("Get unknown should be false")
	}
	all := m.All()
	if len(all) != 2 {
		t.Errorf("All = %d want 2", len(all))
	}
}

func TestResolve_Empty(t *testing.T) {
	m := NewManager()
	if _, _, ok := m.Resolve("anything.example.com"); ok {
		t.Error("empty manager should not match")
	}
}
