// Package domain manages multiple OAST zones and resolves an incoming host or
// QName to its owning domain plus the token label.
package domain

import (
	"strings"

	"github.com/oast/oast/internal/storage"
)

// node is a trie node keyed by reversed DNS labels.
type node struct {
	children map[string]*node
	domain   *storage.Domain // non-nil if this node terminates a configured OAST domain
}

// Manager holds a reversed-label trie over the configured OAST domains for
// longest-suffix matching.
type Manager struct {
	root    *node
	byName  map[string]*storage.Domain
}

// NewManager returns an empty Manager.
func NewManager() *Manager {
	return &Manager{
		root:   &node{children: map[string]*node{}},
		byName: map[string]*storage.Domain{},
	}
}

// Add registers a domain. Adding the same name twice replaces the entry.
func (m *Manager) Add(d *storage.Domain) {
	m.insert(d)
}

// insert walks reversed labels and marks the terminal node.
func (m *Manager) insert(d *storage.Domain) {
	name := normalize(d.Name)
	labels := splitLabels(name) // ["oast","example","com"] for oast.example.com
	cur := m.root
	for i := len(labels) - 1; i >= 0; i-- {
		cur = cur.child(labels[i])
	}
	cur.domain = d
	m.byName[name] = d
}

func (n *node) child(label string) *node {
	c, ok := n.children[label]
	if !ok {
		c = &node{children: map[string]*node{}}
		n.children[label] = c
	}
	return c
}

// Resolve matches host against the trie. It returns:
//   - domain: the owning OAST domain, or nil if none matches
//   - prefix: the labels before the matched suffix, left to right
//     ("" / nil when host == domain). The first label is NOT necessarily the
//     token: dnslog-style exfiltration prepends data labels (data.token.domain).
//     Token resolution is done by the caller (token.MatchToken).
//   - ok: true if a domain matched
//
// Example: domains=[oast.example.com]; host=a1b2.oast.example.com
//   -> domain=oast.example.com, prefix=["a1b2"], ok=true
//   host=data.a1b2.oast.example.com -> domain=..., prefix=["data","a1b2"], ok=true
//   host=oast.example.com -> domain=..., prefix=nil, ok=true
//   host=random.example.com -> nil, nil, false
func (m *Manager) Resolve(host string) (*storage.Domain, []string, bool) {
	name := normalize(host)
	labels := splitLabels(name)
	cur := m.root
	var lastTerminal *storage.Domain
	lastTerminalDepth := 0 // number of labels consumed to reach the terminal
	depth := 0
	for i := len(labels) - 1; i >= 0; i-- {
		next, ok := cur.children[labels[i]]
		if !ok {
			break
		}
		cur = next
		depth++
		if cur.domain != nil {
			lastTerminal = cur.domain
			lastTerminalDepth = depth
		}
	}
	if lastTerminal == nil {
		return nil, nil, false
	}
	// remaining labels (prefix) = labels before the matched suffix
	remaining := len(labels) - lastTerminalDepth
	if remaining <= 0 {
		return lastTerminal, nil, true
	}
	return lastTerminal, labels[:remaining], true
}

// Get returns a registered domain by lowercased name.
func (m *Manager) Get(name string) (*storage.Domain, bool) {
	d, ok := m.byName[normalize(name)]
	return d, ok
}

// All returns all registered domains.
func (m *Manager) All() []*storage.Domain {
	out := make([]*storage.Domain, 0, len(m.byName))
	for _, d := range m.byName {
		out = append(out, d)
	}
	return out
}

func normalize(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

func splitLabels(name string) []string {
	name = strings.TrimSuffix(name, ".")
	if name == "" {
		return nil
	}
	return strings.Split(name, ".")
}
