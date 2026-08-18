package storage

import (
	"context"
	"sort"
	"sync"
	"time"

	"container/list"
)

// Store is the storage abstraction. The only production implementation is
// MemoryStore; the interface exists for testability and future swaps.
type Store interface {
	// Users
	CreateUser(ctx context.Context, u *User) error
	GetUser(ctx context.Context, id int64) (*User, error)
	GetUserByUsername(ctx context.Context, username string) (*User, error)
	UpdateUser(ctx context.Context, u *User) error
	ListUsers(ctx context.Context) ([]*User, error)

	// Projects
	CreateProject(ctx context.Context, p *Project) error
	GetProject(ctx context.Context, id int64) (*Project, error)
	ListProjects(ctx context.Context) ([]*Project, error)
	AddProjectMember(ctx context.Context, m ProjectMember) error

	// Domains
	CreateDomain(ctx context.Context, d *Domain) error
	GetDomain(ctx context.Context, id int64) (*Domain, error)
	GetDomainByName(ctx context.Context, name string) (*Domain, error)
	ListDomains(ctx context.Context) ([]*Domain, error)

	// Tokens
	CreateToken(ctx context.Context, t *Token) error
	GetToken(ctx context.Context, id int64) (*Token, error)
	GetTokenByValue(ctx context.Context, value string) (*Token, error)
	ListTokensByUser(ctx context.Context, userID int64) ([]*Token, error)
	ListTokensByProject(ctx context.Context, projectID int64) ([]*Token, error)
	UpdateTokenStatus(ctx context.Context, id int64, status TokenStatus) error
	RevokeToken(ctx context.Context, id int64) error
	// DeleteToken removes a token entirely (value + indexes). Interactions
	// keep the denormalized TokenValue and therefore survive token deletion.
	DeleteToken(ctx context.Context, id int64) error
	MarkExpiredTokens(ctx context.Context, now time.Time) (int, error)
	// DeletePurgedTokens removes tokens that expired more than grace ago.
	// Interactions survive (they keep the denormalized TokenValue).
	DeletePurgedTokens(ctx context.Context, now time.Time, grace time.Duration) (int, error)

	// Interactions
	AddInteractions(ctx context.Context, batch []Interaction) (int, error)
	GetInteraction(ctx context.Context, id int64) (*Interaction, error)
	ListInteractions(ctx context.Context, f InteractionFilter) ([]Interaction, int, error)
	DeleteInteraction(ctx context.Context, id int64) error
	CountInteractionsByToken(ctx context.Context, tokenValue string) (int, error)
	// InteractionStatsByTokens counts interactions (total + per type) whose
	// TokenValue is in tokenValues. Used for visitor-scoped dashboards.
	InteractionStatsByTokens(ctx context.Context, tokenValues []string) (*Stats, error)
	// DeleteOldInteractions removes interactions with CreatedAt strictly older
	// than `cutoff`. Returns the number of deleted rows.
	DeleteOldInteractions(ctx context.Context, cutoff time.Time) (int, error)

	// Logs
	AddLog(ctx context.Context, l *LogEntry) error
	ListLogs(ctx context.Context, limit int) ([]*LogEntry, error)

	// Refresh tokens
	CreateRefreshToken(ctx context.Context, rt *RefreshToken) error
	GetRefreshTokenByHash(ctx context.Context, hash string) (*RefreshToken, error)
	RevokeRefreshToken(ctx context.Context, id int64) error
	DeleteExpiredRefreshTokens(ctx context.Context, now time.Time) (int, error)

	// Stats / dashboard
	Stats(ctx context.Context) (*Stats, error)

	// Lifecycle
	Close() error
}

// Stats holds dashboard counters.
type Stats struct {
	Users         int64 `json:"users"`
	Projects      int64 `json:"projects"`
	Domains       int64 `json:"domains"`
	Tokens        int64 `json:"tokens"`
	ActiveTokens  int64 `json:"active_tokens"`
	Interactions  int64 `json:"interactions"`
	DNSEvents     int64 `json:"dns_events"`
	HTTPEvents    int64 `json:"http_events"`
	Recent        []Interaction `json:"recent"`
}

// MemoryStore is the single in-memory Store implementation.
// All data is lost on process exit.
type MemoryStore struct {
	mu sync.RWMutex

	// config for capacity protection
	maxInteractions int
	maxPerToken     int
	bodyTruncate    int

	// id generators
	nextID int64

	// users
	users        map[int64]*User
	byUsername  map[string]int64
	byEmail     map[string]int64

	// projects
	projects map[int64]*Project
	members  map[int64]map[int64]ProjectMember // projectID -> userID -> member

	// domains
	domains     map[int64]*Domain
	domainByName map[string]int64

	// tokens
	tokens       map[int64]*Token
	tokenByValue map[string]int64

	// interactions: primary + order + token index
	interactions map[int64]*Interaction
	order        *list.List                    // front = oldest
	idToElem     map[int64]*list.Element        // id -> element in `order`
	byToken      map[string]*list.List         // token_value -> list of ids (front=oldest)
	idToTokenElem map[int64]*list.Element       // id -> element in its byToken list

	// logs
	logs []*LogEntry

	// refresh tokens
	refresh        map[int64]*RefreshToken
	refreshByHash  map[string]int64
}

// NewMemoryStore returns a ready-to-use MemoryStore. bodyTruncate caps the
// stored Interaction.Body length (<=0 falls back to 4096 bytes) so a single
// huge callback body cannot balloon memory.
func NewMemoryStore(maxInteractions, maxPerToken, bodyTruncate int) *MemoryStore {
	if maxInteractions <= 0 {
		maxInteractions = 100000
	}
	if maxPerToken <= 0 {
		maxPerToken = 10000
	}
	if bodyTruncate <= 0 {
		bodyTruncate = 512
	}
	return &MemoryStore{
		maxInteractions: maxInteractions,
		maxPerToken:     maxPerToken,
		bodyTruncate:    bodyTruncate,
		users:           make(map[int64]*User),
		byUsername:      make(map[string]int64),
		byEmail:         make(map[string]int64),
		projects:        make(map[int64]*Project),
		members:         make(map[int64]map[int64]ProjectMember),
		domains:         make(map[int64]*Domain),
		domainByName:    make(map[string]int64),
		tokens:          make(map[int64]*Token),
		tokenByValue:    make(map[string]int64),
		interactions:    make(map[int64]*Interaction),
		order:           list.New(),
		idToElem:        make(map[int64]*list.Element),
		byToken:         make(map[string]*list.List),
		idToTokenElem:   make(map[int64]*list.Element),
		refresh:         make(map[int64]*RefreshToken),
		refreshByHash:   make(map[string]int64),
	}
}

func (s *MemoryStore) Close() error { return nil }

// id allocates a monotonically increasing id. Caller must hold write lock.
func (s *MemoryStore) id() int64 {
	s.nextID++
	return s.nextID
}

// ---- Users ----

func (s *MemoryStore) CreateUser(ctx context.Context, u *User) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if u.Username == "" {
		return ErrValidationT("username required")
	}
	if _, ok := s.byUsername[u.Username]; ok {
		return ErrConflictT("username already exists")
	}
	if u.Email != "" {
		if _, ok := s.byEmail[u.Email]; ok {
			return ErrConflictT("email already exists")
		}
	}
	now := time.Now().UTC()
	u.ID = s.id()
	u.CreatedAt = now
	u.UpdatedAt = now
	if u.Status == "" {
		u.Status = UserActive
	}
	if u.Role == "" {
		u.Role = RoleViewer
	}
	cp := *u
	s.users[cp.ID] = &cp
	s.byUsername[cp.Username] = cp.ID
	if cp.Email != "" {
		s.byEmail[cp.Email] = cp.ID
	}
	*u = cp
	return nil
}

func (s *MemoryStore) GetUser(ctx context.Context, id int64) (*User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.users[id]
	if !ok {
		return nil, ErrNotFoundT("user")
	}
	cp := *u
	return &cp, nil
}

func (s *MemoryStore) GetUserByUsername(ctx context.Context, username string) (*User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, ok := s.byUsername[username]
	if !ok {
		return nil, ErrNotFoundT("user")
	}
	u := s.users[id]
	cp := *u
	return &cp, nil
}

func (s *MemoryStore) UpdateUser(ctx context.Context, u *User) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	ex, ok := s.users[u.ID]
	if !ok {
		return ErrNotFoundT("user")
	}
	if u.Username != ex.Username {
		if _, ok := s.byUsername[u.Username]; ok {
			return ErrConflictT("username already exists")
		}
	}
	if u.Email != "" && u.Email != ex.Email {
		if _, ok := s.byEmail[u.Email]; ok {
			return ErrConflictT("email already exists")
		}
	}
	delete(s.byUsername, ex.Username)
	if ex.Email != "" {
		delete(s.byEmail, ex.Email)
	}
	ex.Username = u.Username
	ex.Email = u.Email
	ex.Role = u.Role
	ex.Status = u.Status
	ex.LastLoginAt = u.LastLoginAt
	ex.UpdatedAt = time.Now().UTC()
	s.byUsername[ex.Username] = ex.ID
	if ex.Email != "" {
		s.byEmail[ex.Email] = ex.ID
	}
	*u = *ex
	return nil
}

func (s *MemoryStore) ListUsers(ctx context.Context) ([]*User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*User, 0, len(s.users))
	for _, u := range s.users {
		cp := *u
		out = append(out, &cp)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// ---- Projects ----

func (s *MemoryStore) CreateProject(ctx context.Context, p *Project) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	p.ID = s.id()
	p.CreatedAt = now
	p.UpdatedAt = now
	cp := *p
	s.projects[cp.ID] = &cp
	*p = cp
	return nil
}

func (s *MemoryStore) GetProject(ctx context.Context, id int64) (*Project, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, ok := s.projects[id]
	if !ok {
		return nil, ErrNotFoundT("project")
	}
	cp := *p
	return &cp, nil
}

func (s *MemoryStore) ListProjects(ctx context.Context) ([]*Project, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*Project, 0, len(s.projects))
	for _, p := range s.projects {
		cp := *p
		out = append(out, &cp)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (s *MemoryStore) AddProjectMember(ctx context.Context, m ProjectMember) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.projects[m.ProjectID]; !ok {
		return ErrNotFoundT("project")
	}
	if _, ok := s.users[m.UserID]; !ok {
		return ErrNotFoundT("user")
	}
	if s.members[m.ProjectID] == nil {
		s.members[m.ProjectID] = make(map[int64]ProjectMember)
	}
	m.JoinedAt = time.Now().UTC()
	s.members[m.ProjectID][m.UserID] = m
	return nil
}

// ---- Domains ----

func (s *MemoryStore) CreateDomain(ctx context.Context, d *Domain) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if d.Name == "" {
		return ErrValidationT("domain name required")
	}
	if _, ok := s.domainByName[d.Name]; ok {
		return ErrConflictT("domain already exists")
	}
	now := time.Now().UTC()
	d.ID = s.id()
	d.CreatedAt = now
	d.UpdatedAt = now
	if d.Status == "" {
		d.Status = "active"
	}
	cp := *d
	s.domains[cp.ID] = &cp
	s.domainByName[cp.Name] = cp.ID
	*d = cp
	return nil
}

func (s *MemoryStore) GetDomain(ctx context.Context, id int64) (*Domain, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	d, ok := s.domains[id]
	if !ok {
		return nil, ErrNotFoundT("domain")
	}
	cp := *d
	return &cp, nil
}

func (s *MemoryStore) GetDomainByName(ctx context.Context, name string) (*Domain, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, ok := s.domainByName[name]
	if !ok {
		return nil, ErrNotFoundT("domain")
	}
	d := s.domains[id]
	cp := *d
	return &cp, nil
}

func (s *MemoryStore) ListDomains(ctx context.Context) ([]*Domain, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*Domain, 0, len(s.domains))
	for _, d := range s.domains {
		cp := *d
		out = append(out, &cp)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// ---- Tokens ----

func (s *MemoryStore) CreateToken(ctx context.Context, t *Token) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if t.Value == "" {
		return ErrValidationT("token value required")
	}
	if _, ok := s.tokenByValue[t.Value]; ok {
		return ErrConflictT("token value already exists")
	}
	now := time.Now().UTC()
	t.ID = s.id()
	t.CreatedAt = now
	if t.Status == "" {
		t.Status = TokenActive
	}
	cp := *t
	s.tokens[cp.ID] = &cp
	s.tokenByValue[cp.Value] = cp.ID
	*t = cp
	return nil
}

func (s *MemoryStore) GetToken(ctx context.Context, id int64) (*Token, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	t, ok := s.tokens[id]
	if !ok {
		return nil, ErrNotFoundT("token")
	}
	cp := *t
	return &cp, nil
}

func (s *MemoryStore) GetTokenByValue(ctx context.Context, value string) (*Token, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, ok := s.tokenByValue[value]
	if !ok {
		return nil, ErrNotFoundT("token")
	}
	t := s.tokens[id]
	cp := *t
	return &cp, nil
}

func (s *MemoryStore) ListTokensByUser(ctx context.Context, userID int64) ([]*Token, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []*Token{}
	for _, t := range s.tokens {
		if t.UserID == userID {
			cp := *t
			out = append(out, &cp)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}

func (s *MemoryStore) ListTokensByProject(ctx context.Context, projectID int64) ([]*Token, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []*Token{}
	for _, t := range s.tokens {
		if t.ProjectID == projectID {
			cp := *t
			out = append(out, &cp)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}

func (s *MemoryStore) UpdateTokenStatus(ctx context.Context, id int64, status TokenStatus) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.tokens[id]
	if !ok {
		return ErrNotFoundT("token")
	}
	t.Status = status
	return nil
}

func (s *MemoryStore) RevokeToken(ctx context.Context, id int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.tokens[id]
	if !ok {
		return ErrNotFoundT("token")
	}
	now := time.Now().UTC()
	t.Status = TokenRevoked
	t.RevokedAt = &now
	return nil
}

func (s *MemoryStore) DeleteToken(ctx context.Context, id int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.tokens[id]
	if !ok {
		return ErrNotFoundT("token")
	}
	delete(s.tokens, id)
	delete(s.tokenByValue, t.Value)
	return nil
}

func (s *MemoryStore) MarkExpiredTokens(ctx context.Context, now time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, t := range s.tokens {
		if t.Status == TokenActive && now.After(t.ExpiresAt) {
			t.Status = TokenExpired
			n++
		}
	}
	return n, nil
}

// DeletePurgedTokens removes tokens that expired more than grace ago.
// Interactions survive (they keep the denormalized TokenValue).
func (s *MemoryStore) DeletePurgedTokens(ctx context.Context, now time.Time, grace time.Duration) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	cutoff := now.Add(-grace)
	for id, t := range s.tokens {
		if t.Status == TokenExpired && cutoff.After(t.ExpiresAt) {
			delete(s.tokens, id)
			delete(s.tokenByValue, t.Value)
			n++
		}
	}
	return n, nil
}

// ---- Interactions ----

// AddInteractions stores a batch and enforces capacity limits.
// Returns the number of interactions actually stored (always len(batch)
// unless context cancelled).
func (s *MemoryStore) AddInteractions(ctx context.Context, batch []Interaction) (int, error) {
	if len(batch) == 0 {
		return 0, nil
	}
	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	default:
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	stored := 0
	for i := range batch {
		iv := batch[i]
		iv.ID = s.id()
		if s.bodyTruncate > 0 && len(iv.Body) > s.bodyTruncate {
			iv.Body = iv.Body[:s.bodyTruncate]
		}
		if iv.CreatedAt.IsZero() {
			iv.CreatedAt = time.Now().UTC()
		} else {
			iv.CreatedAt = iv.CreatedAt.UTC()
		}
		cp := iv
		s.interactions[cp.ID] = &cp
		elem := s.order.PushBack(cp.ID)
		s.idToElem[cp.ID] = elem

		// token index
		tl := s.byToken[cp.TokenValue]
		if tl == nil {
			tl = list.New()
			s.byToken[cp.TokenValue] = tl
		}
		telem := tl.PushBack(cp.ID)
		s.idToTokenElem[cp.ID] = telem

		// per-token cap: evict oldest for this token
		if s.maxPerToken > 0 && tl.Len() > s.maxPerToken {
			front := tl.Front()
			if front != nil {
				evictID := front.Value.(int64)
				s.evictOne(evictID)
			}
		}
		stored++
	}

	// global cap: evict oldest until under limit
	for s.order.Len() > s.maxInteractions {
		front := s.order.Front()
		if front == nil {
			break
		}
		s.evictOne(front.Value.(int64))
	}
	return stored, nil
}

// evictOne removes an interaction by id from primary store + all indexes.
// Caller must hold write lock.
func (s *MemoryStore) evictOne(id int64) {
	iv, ok := s.interactions[id]
	if !ok {
		return
	}
	delete(s.interactions, id)
	if elem := s.idToElem[id]; elem != nil {
		s.order.Remove(elem)
		delete(s.idToElem, id)
	}
	if telem := s.idToTokenElem[id]; telem != nil {
		tl := s.byToken[iv.TokenValue]
		if tl != nil {
			tl.Remove(telem)
			if tl.Len() == 0 {
				delete(s.byToken, iv.TokenValue)
			}
		}
		delete(s.idToTokenElem, id)
	}
}

func (s *MemoryStore) GetInteraction(ctx context.Context, id int64) (*Interaction, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	iv, ok := s.interactions[id]
	if !ok {
		return nil, ErrNotFoundT("interaction")
	}
	cp := *iv
	return &cp, nil
}

// ListInteractions applies f and returns (items, total). total is the count of
// matches ignoring limit/offset, useful for pagination.
func (s *MemoryStore) ListInteractions(ctx context.Context, f InteractionFilter) ([]Interaction, int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	limit := f.Limit
	if limit <= 0 || limit > 500 {
		limit = 50
	}

	// Ownership scope: a non-nil TokenValues (even an EMPTY one) restricts
	// results to interactions owned by those tokens. nil = no scoping.
	// The empty-but-non-nil case must yield zero results (fail-closed).
	var scope map[string]bool
	if f.TokenValues != nil {
		scope = make(map[string]bool, len(f.TokenValues))
		for _, tv := range f.TokenValues {
			scope[tv] = true
		}
	}

	matches := make([]Interaction, 0, limit)
	total := 0

	match := func(iv *Interaction) bool {
		if scope != nil && !scope[iv.TokenValue] {
			return false
		}
		if f.TokenValue != "" && iv.TokenValue != f.TokenValue {
			return false
		}
		if f.Type != "" && iv.Type != f.Type {
			return false
		}
		if f.SrcIP != "" && iv.SrcIP != f.SrcIP {
			return false
		}
		if f.DomainID != 0 && iv.DomainID != f.DomainID {
			return false
		}
		if f.StartTime != nil && iv.CreatedAt.Before(*f.StartTime) {
			return false
		}
		if f.EndTime != nil && iv.CreatedAt.After(*f.EndTime) {
			return false
		}
		return true
	}

	// iterate newest first. When filtering by a single token, use that
	// token's index; when scoping by an ownership set, merge the allowed
	// tokens' lists; otherwise walk the global order list back-to-front.
	var iterate func(yield func(iv *Interaction) bool)
	if scope != nil {
		cand := make([]*Interaction, 0, 64)
		seen := make(map[int64]bool, 64)
		for _, tv := range f.TokenValues {
			tl := s.byToken[tv]
			if tl == nil {
				continue
			}
			for e := tl.Back(); e != nil; e = e.Prev() {
				iv := s.interactions[e.Value.(int64)]
				if iv == nil || seen[iv.ID] {
					continue
				}
				seen[iv.ID] = true
				cand = append(cand, iv)
			}
		}
		sort.Slice(cand, func(i, j int) bool {
			if cand[i].CreatedAt.Equal(cand[j].CreatedAt) {
				return cand[i].ID > cand[j].ID
			}
			return cand[i].CreatedAt.After(cand[j].CreatedAt)
		})
		for _, iv := range cand {
			if !match(iv) {
				continue
			}
			total++
			if total > f.Offset && len(matches) < limit {
				cp := *iv
				matches = append(matches, cp)
			}
		}
		return matches, total, nil
	}
	if f.TokenValue != "" {
		tl := s.byToken[f.TokenValue]
		if tl == nil {
			return matches, 0, nil
		}
		iterate = func(yield func(iv *Interaction) bool) {
			for e := tl.Back(); e != nil; e = e.Prev() {
				iv := s.interactions[e.Value.(int64)]
				if iv == nil {
					continue
				}
				if !yield(iv) {
					return
				}
			}
		}
	} else {
		iterate = func(yield func(iv *Interaction) bool) {
			for e := s.order.Back(); e != nil; e = e.Prev() {
				iv := s.interactions[e.Value.(int64)]
				if iv == nil {
					continue
				}
				if !yield(iv) {
					return
				}
			}
		}
	}

	iterate(func(iv *Interaction) bool {
		if !match(iv) {
			return true
		}
		total++
		if total > f.Offset && len(matches) < limit {
			cp := *iv
			matches = append(matches, cp)
		}
		// Continue walking to compute an accurate total even after the page
		// is full. The byToken index bounds this for the common token-detail
		// query; the global walk is acceptable at admin-console query rates.
		return true
	})

	return matches, total, nil
}

func (s *MemoryStore) DeleteInteraction(ctx context.Context, id int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.interactions[id]; !ok {
		return ErrNotFoundT("interaction")
	}
	s.evictOne(id)
	return nil
}

func (s *MemoryStore) CountInteractionsByToken(ctx context.Context, tokenValue string) (int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	tl := s.byToken[tokenValue]
	if tl == nil {
		return 0, nil
	}
	return tl.Len(), nil
}

// DeleteOldInteractions walks the order list from oldest to newest and removes
// every interaction with CreatedAt strictly older than cutoff. The list is
// front=oldest so we can stop as soon as we hit a non-old entry.
func (s *MemoryStore) DeleteOldInteractions(ctx context.Context, cutoff time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for {
		front := s.order.Front()
		if front == nil {
			break
		}
		iv, ok := s.interactions[front.Value.(int64)]
		if !ok {
			// stale list element; just evict to keep indexes consistent
			s.evictOne(front.Value.(int64))
			continue
		}
		if !iv.CreatedAt.Before(cutoff) {
			break
		}
		s.evictOne(iv.ID)
		n++
	}
	return n, nil
}

// ---- Logs ----

func (s *MemoryStore) AddLog(ctx context.Context, l *LogEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	l.ID = s.id()
	l.CreatedAt = now
	cp := *l
	s.logs = append(s.logs, &cp)
	// cap logs to 100k to bound memory
	if len(s.logs) > 100000 {
		s.logs = s.logs[len(s.logs)-100000:]
	}
	*l = cp
	return nil
}

func (s *MemoryStore) ListLogs(ctx context.Context, limit int) ([]*LogEntry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	n := len(s.logs)
	if n == 0 {
		return []*LogEntry{}, nil
	}
	start := n - limit
	if start < 0 {
		start = 0
	}
	out := make([]*LogEntry, 0, limit)
	for i := start; i < n; i++ {
		cp := *s.logs[i]
		out = append(out, &cp)
	}
	// reverse to newest first
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out, nil
}

// ---- Refresh tokens ----

func (s *MemoryStore) CreateRefreshToken(ctx context.Context, rt *RefreshToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if rt.TokenHash == "" {
		return ErrValidationT("token_hash required")
	}
	if _, ok := s.refreshByHash[rt.TokenHash]; ok {
		return ErrConflictT("refresh token already exists")
	}
	now := time.Now().UTC()
	rt.ID = s.id()
	rt.CreatedAt = now
	cp := *rt
	s.refresh[cp.ID] = &cp
	s.refreshByHash[cp.TokenHash] = cp.ID
	*rt = cp
	return nil
}

func (s *MemoryStore) GetRefreshTokenByHash(ctx context.Context, hash string) (*RefreshToken, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, ok := s.refreshByHash[hash]
	if !ok {
		return nil, ErrNotFoundT("refresh token")
	}
	rt := s.refresh[id]
	cp := *rt
	return &cp, nil
}

func (s *MemoryStore) RevokeRefreshToken(ctx context.Context, id int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	rt, ok := s.refresh[id]
	if !ok {
		return ErrNotFoundT("refresh token")
	}
	now := time.Now().UTC()
	rt.RevokedAt = &now
	return nil
}

func (s *MemoryStore) DeleteExpiredRefreshTokens(ctx context.Context, now time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for id, rt := range s.refresh {
		if now.After(rt.ExpiresAt) || (rt.RevokedAt != nil && now.Sub(*rt.RevokedAt) > 24*time.Hour) {
			delete(s.refresh, id)
			delete(s.refreshByHash, rt.TokenHash)
			n++
		}
	}
	return n, nil
}

// ---- Stats ----

func (s *MemoryStore) Stats(ctx context.Context) (*Stats, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	st := &Stats{
		Users:        int64(len(s.users)),
		Projects:     int64(len(s.projects)),
		Domains:      int64(len(s.domains)),
		Tokens:       int64(len(s.tokens)),
		Interactions: int64(len(s.interactions)),
	}
	for _, t := range s.tokens {
		if t.Status == TokenActive {
			st.ActiveTokens++
		}
	}
	for _, iv := range s.interactions {
		switch iv.Type {
		case InteractionDNS:
			st.DNSEvents++
		case InteractionHTTP:
			st.HTTPEvents++
		}
	}
	// recent 10
	st.Recent = make([]Interaction, 0, 10)
	for e, n := s.order.Back(), 0; e != nil && n < 10; e, n = e.Prev(), n+1 {
		iv := s.interactions[e.Value.(int64)]
		if iv != nil {
			st.Recent = append(st.Recent, *iv)
		}
	}
	return st, nil
}

// InteractionStatsByTokens returns visitor-scoped counters for the given
// token values: total interactions, per-type counts and the 10 most recent.
func (s *MemoryStore) InteractionStatsByTokens(ctx context.Context, tokenValues []string) (*Stats, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	all := make([]*Interaction, 0, 64)
	seen := make(map[int64]bool, 64)
	for _, tv := range tokenValues {
		tl := s.byToken[tv]
		if tl == nil {
			continue
		}
		for e := tl.Front(); e != nil; e = e.Next() {
			iv := s.interactions[e.Value.(int64)]
			if iv == nil || seen[iv.ID] {
				continue
			}
			seen[iv.ID] = true
			all = append(all, iv)
		}
	}
	sort.Slice(all, func(i, j int) bool { return all[i].ID > all[j].ID })

	st := &Stats{
		Interactions: int64(len(all)),
		Recent:       make([]Interaction, 0, min(10, len(all))),
	}
	for _, iv := range all {
		switch iv.Type {
		case InteractionDNS:
			st.DNSEvents++
		case InteractionHTTP:
			st.HTTPEvents++
		}
	}
	for i := 0; i < len(all) && i < 10; i++ {
		st.Recent = append(st.Recent, *all[i])
	}
	return st, nil
}
