// Package api implements the OAST admin HTTP API: dashboard, interaction
// listing, token lifecycle, and an optional dnslog-style cookie session gate.
package api

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"math"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/oast/oast/internal/config"
	"github.com/oast/oast/internal/storage"
	"github.com/oast/oast/internal/token"
	"github.com/oast/oast/internal/web"
)

// Server is the admin HTTP API server.
type Server struct {
	cfg      config.Config
	store    storage.Store
	tokens   *token.Manager
	log      *slog.Logger

	sessSecret []byte
	sessMaxAge time.Duration

	limiter loginLimiter

	httpSrv *http.Server
}

// New returns a configured but not-yet-started Server.
func New(cfg config.Config, store storage.Store, tm *token.Manager, log *slog.Logger) *Server {
	return &Server{
		cfg:        cfg,
		store:      store,
		tokens:     tm,
		log:        log,
		sessSecret: []byte(cfg.Auth.JWTSecret),
		sessMaxAge: cfg.Auth.RefreshTTL,
	}
}

// Start launches the admin server (HTTP or HTTPS depending on TLS config).
func (s *Server) Start() error {
	r := chi.NewRouter()
	r.Use(middleware.Recoverer)
	r.Use(peerIPMiddleware) // must run before RealIP so the limiter sees the socket peer
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(s.visitorMiddleware)
	if s.cfg.Server.Admin.EnablePprof {
		r.Mount("/debug", middleware.Profiler())
	}

	r.Get("/healthz", s.handleHealth)
	r.Get("/login", s.handleLoginPage)
	r.Post("/login", s.handleLogin)
	r.Post("/logout", s.handleLogout)
	r.Get("/api/config", s.handlePublicConfig)

	r.Group(func(r chi.Router) {
		r.Use(s.authMiddleware)
		r.Get("/api/stats", s.handleStats)
		r.Get("/api/interactions", s.handleListInteractions)
		r.Get("/api/interactions/{id}", s.handleGetInteraction)
		r.Delete("/api/interactions/{id}", s.handleDeleteInteraction)
		r.Get("/api/tokens", s.handleListTokens)
		r.Post("/api/tokens", s.handleCreateToken)
		r.Delete("/api/tokens/{value}", s.handleDeleteToken)
		r.Get("/api/domains", s.handleListDomains)
	})

	// Static dashboard: serve index.html at / and assets at /static/.
	staticFS, _ := fs.Sub(web.StaticFS, web.StaticDir)
	r.Handle("/static/*", http.StripPrefix("/static/", http.FileServer(http.FS(staticFS))))
	r.Get("/", s.handleDashboard)

	s.httpSrv = &http.Server{
		Addr:              s.cfg.Server.Admin.Listen,
		Handler:           r,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
	}

	ln, err := net.Listen("tcp", s.cfg.Server.Admin.Listen)
	if err != nil {
		return fmt.Errorf("admin listen %s: %w", s.cfg.Server.Admin.Listen, err)
	}
	tls := s.cfg.Server.Admin.TLSCert != "" && s.cfg.Server.Admin.TLSKey != ""
	go func() {
		s.log.Info("admin listening", "addr", s.cfg.Server.Admin.Listen,
			"tls", tls, "auth", s.cfg.Auth.Password != "")
		var err error
		if tls {
			err = s.httpSrv.ServeTLS(ln, s.cfg.Server.Admin.TLSCert, s.cfg.Server.Admin.TLSKey)
		} else {
			err = s.httpSrv.Serve(ln)
		}
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.log.Error("admin serve ended", "err", err)
		}
	}()
	return nil
}

// Shutdown stops the admin server with a 5s budget.
func (s *Server) Shutdown() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if s.httpSrv != nil {
		_ = s.httpSrv.Shutdown(ctx)
	}
}

// ---- helpers ----

// visitorCookie names the anonymous per-browser identity cookie that isolates
// each visitor's tokens and interactions from every other browser.
const visitorCookie = "oast_vid"

type ctxKey int

const ctxVisitor ctxKey = iota

// newVisitorID returns a random positive int64 identity for an anonymous
// browser session.
func newVisitorID() int64 {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return time.Now().UnixNano() & math.MaxInt64
	}
	v := int64(binary.BigEndian.Uint64(b[:]) & math.MaxInt64)
	if v == 0 {
		v = 1
	}
	return v
}

// visitorMiddleware guarantees every browser carries an anonymous visitor
// cookie (oast_vid). Tokens are bound to that visitor ID and every read /
// write of tokens & interactions is scoped to it, so different browsers can
// never see each other's data — even when the admin is fully open.
func (s *Server) visitorMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		vid := int64(0)
		if c, err := r.Cookie(visitorCookie); err == nil {
			if v, perr := strconv.ParseInt(c.Value, 10, 64); perr == nil && v > 0 {
				vid = v
			}
		}
		if vid == 0 {
			vid = newVisitorID()
			maxAge := int(s.cfg.Auth.VisitorTTL / time.Second)
			if maxAge <= 0 {
				maxAge = 604800 // 7d fallback
			}
			http.SetCookie(w, &http.Cookie{
				Name:     visitorCookie,
				Value:    strconv.FormatInt(vid, 10),
				Path:     "/",
				HttpOnly: true,
				Secure:   r.TLS != nil,
				MaxAge:   maxAge,
				SameSite: http.SameSiteLaxMode,
			})
		}
		ctx := context.WithValue(r.Context(), ctxVisitor, vid)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// visitorID returns the anonymous visitor identity from the request context.
func visitorID(r *http.Request) int64 {
	if v, ok := r.Context().Value(ctxVisitor).(int64); ok {
		return v
	}
	return 0
}

// ---- login rate limiting: cap failures per socket peer IP ----

type loginLimiter struct {
	mu    sync.Mutex
	fails map[string][]time.Time
}

const (
	loginWindow  = 5 * time.Minute
	loginMaxFail = 10
)

func (l *loginLimiter) allow(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.prune(ip, time.Now().Add(-loginWindow))
	return len(l.fails[ip]) < loginMaxFail
}

func (l *loginLimiter) fail(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.fails == nil {
		l.fails = map[string][]time.Time{}
	}
	l.prune(ip, time.Now().Add(-loginWindow))
	l.fails[ip] = append(l.fails[ip], time.Now())
}

func (l *loginLimiter) prune(ip string, cutoff time.Time) {
	fs := l.fails[ip]
	keep := fs[:0]
	for _, t := range fs {
		if t.After(cutoff) {
			keep = append(keep, t)
		}
	}
	if len(keep) == 0 {
		delete(l.fails, ip)
		return
	}
	l.fails[ip] = keep
}

// peerIPKey is a distinct context-key type so it cannot collide with ctxVisitor.
type peerIPKey struct{}

var ctxPeerIP = peerIPKey{}

// peerIPMiddleware must be registered BEFORE middleware.RealIP: it captures
// the real socket address so a forged X-Forwarded-For cannot bypass the
// login rate limiter.
func peerIPMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			ip = r.RemoteAddr
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxPeerIP, ip)))
	})
}

func peerIP(r *http.Request) string {
	if v, ok := r.Context().Value(ctxPeerIP).(string); ok && v != "" {
		return v
	}
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	return ip
}

// ownsInteraction reports whether the visitor's token set contains the
// interaction's token value.
func (s *Server) ownsInteraction(r *http.Request, iv *storage.Interaction) bool {
	if iv == nil {
		return false
	}
	tk, err := s.store.GetTokenByValue(r.Context(), iv.TokenValue)
	if err != nil {
		return false
	}
	return tk.UserID == visitorID(r)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// sessionToken returns "<unixTs>.<hmac>" for the given timestamp.
func (s *Server) sessionToken(ts int64) string {
	payload := fmt.Sprintf("%d", ts)
	mac := hmac.New(sha256.New, s.sessSecret)
	mac.Write([]byte(payload))
	return payload + "." + hex.EncodeToString(mac.Sum(nil))
}

// validSession returns true if the cookie value is a valid, non-expired session.
func (s *Server) validSession(cookie string) bool {
	parts := strings.SplitN(cookie, ".", 2)
	if len(parts) != 2 {
		return false
	}
	ts, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return false
	}
	if s.sessMaxAge > 0 && time.Now().Unix()-ts > int64(s.sessMaxAge/time.Second) {
		return false
	}
	mac := hmac.New(sha256.New, s.sessSecret)
	mac.Write([]byte(parts[0]))
	expected := hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(expected), []byte(parts[1]))
}

// authRequired returns true when the admin UI is gated by a password.
func (s *Server) authRequired() bool { return s.cfg.Auth.Password != "" }

// authMiddleware enforces the cookie session when auth.password is set.
func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.authRequired() {
			next.ServeHTTP(w, r)
			return
		}
		c, err := r.Cookie("oast_sess")
		if err != nil || !s.validSession(c.Value) {
			// For API requests, return 401 JSON; for browser navigation,
			// redirect to /login.
			if strings.HasPrefix(r.URL.Path, "/api/") {
				writeErr(w, http.StatusUnauthorized, "unauthorized")
				return
			}
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// ---- handlers ----

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *Server) handlePublicConfig(w http.ResponseWriter, r *http.Request) {
	// Only exposes whether auth is required; nothing sensitive.
	writeJSON(w, 200, map[string]any{
		"auth_required": s.authRequired(),
		"version":      "dev",
	})
}

func (s *Server) handleLoginPage(w http.ResponseWriter, r *http.Request) {
	if !s.authRequired() {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(200)
	_, _ = w.Write([]byte(`<!DOCTYPE html><html><head><meta charset="utf-8"><title>OAST Login</title>
<style>body{font-family:system-ui;background:#0d1117;color:#c9d1d9;display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0}
.box{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:30px;width:320px}
h2{margin:0 0 20px;color:#fff}input{width:100%;padding:8px;background:#0d1117;color:#c9d1d9;border:1px solid #30363d;border-radius:4px;font-size:14px;box-sizing:border-box}
button{width:100%;margin-top:12px;padding:8px;background:#2f81f7;color:#fff;border:none;border-radius:4px;cursor:pointer}
.err{color:#f85149;font-size:12px;margin-top:10px}</style></head>
<body><div class="box"><h2>访问密码</h2>
<form method="POST" action="/login"><input type="password" name="password" autofocus>
<button type="submit">进入</button></form></div></body></html>`))
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if !s.authRequired() {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	if err := r.ParseForm(); err != nil {
		writeErr(w, 400, "bad form")
		return
	}
	pw := r.FormValue("password")
	ip := peerIP(r)
	if !s.limiter.allow(ip) {
		writeErr(w, 429, "too many failed attempts; try again later")
		return
	}
	if !hmac.Equal([]byte(pw), []byte(s.cfg.Auth.Password)) {
		s.limiter.fail(ip)
		w.WriteHeader(401)
		_, _ = w.Write([]byte(`<p class="err">密码错误</p><p><a href="/login">重试</a></p>`))
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "oast_sess",
		Value:    s.sessionToken(time.Now().Unix()),
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil,
		MaxAge:   int(s.sessMaxAge / time.Second),
		SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     "oast_sess",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	if s.authRequired() {
		c, err := r.Cookie("oast_sess")
		if err != nil || !s.validSession(c.Value) {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
	}
	staticFS, _ := fs.Sub(web.StaticFS, web.StaticDir)
	data, err := fs.ReadFile(staticFS, "index.html")
	if err != nil {
		writeErr(w, 500, "dashboard not embedded")
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(200)
	_, _ = w.Write(data)
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	tks, err := s.store.ListTokensByUser(ctx, visitorID(r))
	if err != nil {
		writeErr(w, 500, "stats: "+err.Error())
		return
	}
	vals := make([]string, 0, len(tks)) // non-nil: a visitor with no tokens gets an empty scope
	for _, t := range tks {
		vals = append(vals, t.Value)
	}
	st, err := s.store.InteractionStatsByTokens(ctx, vals)
	if err != nil {
		writeErr(w, 500, "stats: "+err.Error())
		return
	}
	st.Tokens = int64(len(tks))
	for _, t := range tks {
		if t.Status == storage.TokenActive {
			st.ActiveTokens++
		}
	}
	doms, _ := s.store.ListDomains(ctx)
	st.Domains = int64(len(doms))
	writeJSON(w, 200, st)
}

func (s *Server) handleListInteractions(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	q := r.URL.Query()
	// Ownership scope: only the caller's own tokens are ever visible.
	// vals is always non-nil — an empty token set means an empty result,
	// never a fall-through to the global walk.
	tks, err := s.store.ListTokensByUser(ctx, visitorID(r))
	if err != nil {
		writeErr(w, 500, "list tokens: "+err.Error())
		return
	}
	vals := make([]string, 0, len(tks))
	for _, t := range tks {
		vals = append(vals, t.Value)
	}
	f := storage.InteractionFilter{
		TokenValue:  q.Get("token"),
		SrcIP:       q.Get("src_ip"),
		TokenValues: vals,
	}
	if t := q.Get("type"); t == "dns" || t == "http" {
		f.Type = storage.InteractionType(t)
	}
	if v := q.Get("limit"); v != "" {
		f.Limit, _ = strconv.Atoi(v)
	}
	if v := q.Get("offset"); v != "" {
		f.Offset, _ = strconv.Atoi(v)
	}
	items, total, err := s.store.ListInteractions(ctx, f)
	if err != nil {
		writeErr(w, 500, "list: "+err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{
		"items": items,
		"total": total,
	})
}

func (s *Server) handleGetInteraction(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		writeErr(w, 400, "bad id")
		return
	}
	iv, err := s.store.GetInteraction(r.Context(), id)
	if err != nil || !s.ownsInteraction(r, iv) {
		writeErr(w, 404, "not found")
		return
	}
	writeJSON(w, 200, iv)
}

func (s *Server) handleDeleteInteraction(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		writeErr(w, 400, "bad id")
		return
	}
	iv, err := s.store.GetInteraction(r.Context(), id)
	if err != nil || !s.ownsInteraction(r, iv) {
		writeErr(w, 404, "not found")
		return
	}
	if err := s.store.DeleteInteraction(r.Context(), id); err != nil {
		writeErr(w, 500, "delete: "+err.Error())
		return
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (s *Server) handleListTokens(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	// Anonymous visitors are isolated: each browser only sees the tokens it
	// created itself (tokens are bound to the visitor ID as UserID).
	tks, _ := s.store.ListTokensByUser(ctx, visitorID(r))
	type tkOut struct {
		Value     string    `json:"value"`
		Domain    string    `json:"domain"`
		Status    string    `json:"status"`
		Note      string    `json:"note,omitempty"`
		CreatedAt time.Time `json:"created_at"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	out := make([]tkOut, 0, len(tks))
	for _, t := range tks {
		dom, _ := s.store.GetDomain(ctx, t.DomainID)
		domName := ""
		if dom != nil {
			domName = dom.Name
		}
		out = append(out, tkOut{
			Value:     t.Value,
			Domain:    domName,
			Status:    string(t.Status),
			Note:      t.Note,
			CreatedAt: t.CreatedAt,
			ExpiresAt: t.ExpiresAt,
		})
	}
	writeJSON(w, 200, map[string]any{"tokens": out})
}

func (s *Server) handleCreateToken(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	// Per-visitor token cap: keeps an open (passwordless) admin from being
	// flooded with unlimited tokens.
	const maxTokensPerVisitor = 20
	if tks, err := s.store.ListTokensByUser(ctx, visitorID(r)); err == nil && len(tks) >= maxTokensPerVisitor {
		writeErr(w, 429, "token limit reached; delete unused tokens first")
		return
	}
	doms, err := s.store.ListDomains(ctx)
	if err != nil || len(doms) == 0 {
		writeErr(w, 500, "no domains configured")
		return
	}
	// Pick the explicit domain when given (?domain=<name>), otherwise the first one.
	dom := doms[0]
	if name := r.URL.Query().Get("domain"); name != "" {
		d, err := s.store.GetDomainByName(ctx, name)
		if err != nil {
			writeErr(w, 400, "unknown domain: "+name)
			return
		}
		dom = d
	}

	// Retry on the rare value collision so short tokens stay safe.
	var val string
	for attempt := 0; attempt < 8; attempt++ {
		v, err := token.Generate()
		if err != nil {
			writeErr(w, 500, "generate: "+err.Error())
			return
		}
		tk := &storage.Token{
			Value:     v,
			DomainID:  dom.ID,
			UserID:    visitorID(r),
			Status:    storage.TokenActive,
			ExpiresAt: time.Now().Add(s.cfg.Token.DefaultTTL).UTC(),
		}
		if err := s.store.CreateToken(ctx, tk); err != nil {
			if storage.AsConflict(err) {
				continue // collision, retry
			}
			writeErr(w, 500, "create: "+err.Error())
			return
		}
		val = v
		break
	}
	if val == "" {
		writeErr(w, 500, "could not generate unique token after retries")
		return
	}
	writeJSON(w, 201, map[string]string{
		"value":  val,
		"domain": dom.Name,
	})
}

func (s *Server) handleDeleteToken(w http.ResponseWriter, r *http.Request) {
	val := chi.URLParam(r, "value")
	tk, err := s.store.GetTokenByValue(r.Context(), val)
	if err != nil || tk.UserID != visitorID(r) {
		// Not found for anyone but the owner.
		writeErr(w, 404, "token not found")
		return
	}
	// Hard delete: the token must disappear from the dashboard list. Past
	// interactions keep their denormalized TokenValue and remain visible.
	if err := s.store.DeleteToken(r.Context(), tk.ID); err != nil {
		writeErr(w, 500, "delete: "+err.Error())
		return
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (s *Server) handleListDomains(w http.ResponseWriter, r *http.Request) {
	doms, err := s.store.ListDomains(r.Context())
	if err != nil {
		writeErr(w, 500, "list: "+err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"domains": doms})
}
