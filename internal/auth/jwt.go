package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/oast/oast/internal/storage"
)

// Claims is the JWT payload for access tokens.
type Claims struct {
	UserID int64          `json:"uid"`
	Role   storage.Role   `json:"role"`
	jwt.RegisteredClaims
}

// JWT issues and verifies access tokens; refresh tokens are opaque strings
// whose sha256 hash is stored in the Store for revocation.
type JWT struct {
	secret     []byte
	accessTTL  time.Duration
	refreshTTL time.Duration
}

// NewJWT returns a JWT helper.
func NewJWT(secret string, accessTTL, refreshTTL time.Duration) *JWT {
	return &JWT{
		secret:     []byte(secret),
		accessTTL:  accessTTL,
		refreshTTL: refreshTTL,
	}
}

// IssueAccess returns a signed access token for the given user.
func (j *JWT) IssueAccess(u *storage.User) (string, error) {
	now := time.Now().UTC()
	claims := Claims{
		UserID: u.ID,
		Role:   u.Role,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   fmt.Sprintf("%d", u.ID),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(j.accessTTL)),
			NotBefore: jwt.NewNumericDate(now),
		},
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return tok.SignedString(j.secret)
}

// VerifyAccess parses and validates an access token, returning its claims.
func (j *JWT) VerifyAccess(tokenStr string) (*Claims, error) {
	claims := &Claims{}
	_, err := jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return j.secret, nil
	})
	if err != nil {
		return nil, fmt.Errorf("verify access token: %w", err)
	}
	return claims, nil
}

// GenerateRefresh returns a new opaque refresh token string (256-bit entropy).
// The caller should persist its sha256 hash via the Store.
func (j *JWT) GenerateRefresh() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// HashRefresh returns the sha256 hex of a refresh token. Storing the hash (not
// the raw token) limits damage if the store is leaked.
func HashRefresh(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// RefreshTTL returns the configured refresh token TTL.
func (j *JWT) RefreshTTL() time.Duration { return j.refreshTTL }

// AccessTTL returns the configured access token TTL.
func (j *JWT) AccessTTL() time.Duration { return j.accessTTL }

// ErrInvalidToken is returned when a token is malformed or expired.
var ErrInvalidToken = errors.New("invalid token")
