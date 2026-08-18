package token

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/oast/oast/internal/storage"
)

// Manager creates tokens and manages their lifecycle. It depends on a Store.
type Manager struct {
	store      storage.Store
	defaultTTL time.Duration
}

// NewManager returns a token Manager.
func NewManager(store storage.Store, defaultTTL time.Duration) *Manager {
	if defaultTTL <= 0 {
		defaultTTL = 168 * time.Hour
	}
	return &Manager{store: store, defaultTTL: defaultTTL}
}

// CreateRequest is the input to create a token.
type CreateRequest struct {
	UserID    int64
	ProjectID int64
	DomainID  int64
	Note      string
	TTL       time.Duration // 0 = defaultTTL
}

// Create generates a unique token value, stores it, and returns the stored Token.
// It retries generation on the rare collision (returns error after 8 tries).
func (m *Manager) Create(ctx context.Context, req CreateRequest) (*storage.Token, error) {
	if req.UserID == 0 {
		return nil, errors.New("user_id required")
	}
	if req.ProjectID == 0 {
		return nil, errors.New("project_id required")
	}
	if req.DomainID == 0 {
		return nil, errors.New("domain_id required")
	}
	ttl := req.TTL
	if ttl <= 0 {
		ttl = m.defaultTTL
	}
	expires := time.Now().Add(ttl).UTC()

	var lastErr error
	for attempt := 0; attempt < 8; attempt++ {
		val, err := Generate()
		if err != nil {
			lastErr = err
			continue
		}
		tk := &storage.Token{
			Value:     val,
			DomainID:  req.DomainID,
			UserID:    req.UserID,
			ProjectID: req.ProjectID,
			Status:    storage.TokenActive,
			ExpiresAt: expires,
			Note:      req.Note,
		}
		if err := m.store.CreateToken(ctx, tk); err != nil {
			if storage.AsConflict(err) {
				lastErr = err
				continue // collision, retry
			}
			return nil, err
		}
		return tk, nil
	}
	return nil, fmt.Errorf("could not generate unique token after retries: %w", lastErr)
}

// Revoke marks a token revoked.
func (m *Manager) Revoke(ctx context.Context, id int64) error {
	return m.store.RevokeToken(ctx, id)
}

// Resolve looks up a token by its value (called from DNS/HTTP handlers).
func (m *Manager) Resolve(ctx context.Context, value string) (*storage.Token, error) {
	return m.store.GetTokenByValue(ctx, value)
}

// SweepExpired marks active tokens past their expiry as expired.
// Intended to be called periodically.
func (m *Manager) SweepExpired(ctx context.Context) (int, error) {
	return m.store.MarkExpiredTokens(ctx, time.Now())
}

// DefaultTTL returns the configured default TTL.
func (m *Manager) DefaultTTL() time.Duration { return m.defaultTTL }
