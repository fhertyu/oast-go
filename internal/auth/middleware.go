package auth

import (
	"context"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/oast/oast/internal/storage"
)

type contextKey string

const (
	ctxUser contextKey = "user"
)

// WithUser stores the authenticated user in the request context.
func WithUser(ctx context.Context, u *storage.User) context.Context {
	return context.WithValue(ctx, ctxUser, u)
}

// UserFromContext returns the authenticated user or nil.
func UserFromContext(ctx context.Context) *storage.User {
	v, _ := ctx.Value(ctxUser).(*storage.User)
	return v
}

// Authenticator is chi middleware that validates a Bearer access token.
type Authenticator struct {
	jwt *JWT
}

func NewAuthenticator(j *JWT) *Authenticator { return &Authenticator{jwt: j} }

// Middleware returns a chi-compatible middleware.
func (a *Authenticator) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header := r.Header.Get("Authorization")
		if header == "" {
			http.Error(w, "missing Authorization header", http.StatusUnauthorized)
			return
		}
		const prefix = "Bearer "
		if !strings.HasPrefix(header, prefix) {
			http.Error(w, "invalid Authorization scheme", http.StatusUnauthorized)
			return
		}
		tokenStr := strings.TrimSpace(header[len(prefix):])
		claims, err := a.jwt.VerifyAccess(tokenStr)
		if err != nil {
			http.Error(w, "invalid token", http.StatusUnauthorized)
			return
		}
		// We trust the role from the token; refresh-time role changes require
		// re-login. The full user object is reconstructed from claims.
		u := &storage.User{ID: claims.UserID, Role: claims.Role}
		r = r.WithContext(WithUser(r.Context(), u))
		next.ServeHTTP(w, r)
	})
}

// Require is a chi-compatible middleware factory that enforces permissions.
// It must run AFTER Authenticator.
func Require(perms ...Permission) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			u := UserFromContext(r.Context())
			if u == nil {
				http.Error(w, "unauthenticated", http.StatusUnauthorized)
				return
			}
			if missing := Missing(u.Role, perms...); len(missing) > 0 {
				http.Error(w, "forbidden: missing "+joinPerms(missing), http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// Router is the convenience auth-protected sub-router builder.
func (a *Authenticator) Protected(r chi.Router, perms ...Permission) chi.Router {
	sub := chi.NewRouter()
	sub.Use(a.Middleware)
	if len(perms) > 0 {
		sub.Use(Require(perms...))
	}
	r.Mount("/", sub)
	return sub
}

func joinPerms(ps []Permission) string {
	parts := make([]string, len(ps))
	for i, p := range ps {
		parts[i] = string(p)
	}
	return strings.Join(parts, ",")
}
