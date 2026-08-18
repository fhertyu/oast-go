// Package httpserver implements the OAST HTTP(S) callback collector: any
// request received against a configured OAST domain (matched via the Host
// header) is recorded as an Interaction and answered with a benign response.
//
// The collector deliberately accepts ALL paths, methods and bodies — its job
// is to capture attacker callbacks, not to serve content. Auth happens at the
// admin API layer (internal/api); the collector is intentionally open.
package httpserver

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/oast/oast/internal/config"
	"github.com/oast/oast/internal/domain"
	"github.com/oast/oast/internal/interaction"
	"github.com/oast/oast/internal/storage"
	"github.com/oast/oast/internal/token"
)

// Server runs the OAST HTTP collector (plain HTTP, plus optional TLS).
type Server struct {
	cfg          config.HTTPConfig
	domains      *domain.Manager
	bus          *interaction.Bus
	store        storage.Store
	log          *slog.Logger
	bodyTruncate int // edge truncation: cap bytes read from the request body

	httpSrv *http.Server
	tlsSrv  *http.Server

	requests atomic.Uint64
}

// New returns a configured but not-yet-started Server. bodyTruncate caps the
// request body at the collection edge (before it enters the bus queue) so
// memory stays bounded regardless of burst size; storage truncates again as
// a second guard.
func New(cfg config.HTTPConfig, dm *domain.Manager, bus *interaction.Bus, store storage.Store, bodyTruncate int, log *slog.Logger) *Server {
	if bodyTruncate <= 0 {
		bodyTruncate = 512
	}
	return &Server{cfg: cfg, domains: dm, bus: bus, store: store, log: log, bodyTruncate: bodyTruncate}
}

// Start launches the configured listeners. Listeners are pre-bound so a port
// conflict fails fast (returns an error) instead of being logged from a
// goroutine after startup "succeeded". Call Shutdown to stop. If TLS
// cert/key are not set, the TLS listener is skipped.
func (s *Server) Start() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handle)

	if s.cfg.Listen != "" {
		ln, err := net.Listen("tcp", s.cfg.Listen)
		if err != nil {
			return fmt.Errorf("http listen %s: %w", s.cfg.Listen, err)
		}
		s.httpSrv = &http.Server{
			Handler:           mux,
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       30 * time.Second,
			WriteTimeout:      10 * time.Second,
		}
		go func() {
			s.log.Info("http listening", "addr", s.cfg.Listen)
			if err := s.httpSrv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
				s.log.Error("http serve ended", "err", err)
			}
		}()
	}

	if s.cfg.TLSListen != "" && s.cfg.TLSCert != "" && s.cfg.TLSKey != "" {
		ln, err := net.Listen("tcp", s.cfg.TLSListen)
		if err != nil {
			return fmt.Errorf("https listen %s: %w", s.cfg.TLSListen, err)
		}
		s.tlsSrv = &http.Server{
			Handler:           mux,
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       30 * time.Second,
			WriteTimeout:      10 * time.Second,
		}
		go func() {
			s.log.Info("https listening", "addr", s.cfg.TLSListen)
			if err := s.tlsSrv.ServeTLS(ln, s.cfg.TLSCert, s.cfg.TLSKey); err != nil && !errors.Is(err, http.ErrServerClosed) {
				s.log.Error("https serve ended", "err", err)
			}
		}()
	}
	return nil
}

// Shutdown stops the listeners with a 5s budget.
func (s *Server) Shutdown() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if s.httpSrv != nil {
		_ = s.httpSrv.Shutdown(ctx)
	}
	if s.tlsSrv != nil {
		_ = s.tlsSrv.Shutdown(ctx)
	}
}

// Requests returns the total number of requests handled.
func (s *Server) Requests() uint64 { return s.requests.Load() }

// handle is the universal OAST callback handler. It records every request
// whose Host matches a configured OAST zone, regardless of method or path.
func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	s.requests.Add(1)

	host := stripPort(r.Host)
	if host == "" {
		host = stripPort(r.RemoteAddr)
	}
	dom, prefix, ok := s.domains.Resolve(host)
	if !ok {
		// Not an OAST domain — answer with 404 to avoid behaving like an open proxy.
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("404 not found\n"))
		return
	}
	tokenValue, _ := token.MatchToken(r.Context(), s.store, prefix)

	// Edge truncation: never read more than bodyTruncate bytes into memory
	// (BodyReadLimit only serves as an upper fallback when unset).
	bodyLimit := int64(s.bodyTruncate)
	if bodyLimit <= 0 {
		bodyLimit = s.cfg.BodyReadLimit
	}
	if bodyLimit <= 0 {
		bodyLimit = 1 << 20
	}
	var buf bytes.Buffer
	if r.Body != nil {
		_, _ = io.Copy(&buf, io.LimitReader(r.Body, bodyLimit+1))
		if int64(buf.Len()) > bodyLimit {
			buf.Truncate(int(bodyLimit))
		}
	}

	iv := storage.Interaction{
		Type:       storage.InteractionHTTP,
		SubType:    r.Method,
		Protocol:   schemeOf(r),
		Method:     r.Method,
		Path:       trunc(r.URL.Path, maxPathQueryBytes),
		Query:      trunc(r.URL.RawQuery, maxPathQueryBytes),
		Headers:    flattenHeaders(r.Header),
		Cookie:     trunc(r.Header.Get("Cookie"), maxSmallFieldBytes),
		UserAgent:  trunc(r.UserAgent(), maxSmallFieldBytes),
		Referer:    trunc(r.Referer(), maxSmallFieldBytes),
		Body:       buf.String(),
		TokenValue: tokenValue,
		Labels:     prefix,
		DomainID:   dom.ID,
	}
	srcIP, srcPort := splitHostPort(r.RemoteAddr)
	iv.SrcIP = srcIP
	iv.SrcPort = srcPort
	_ = s.bus.Submit(iv)

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok\n"))
}

// schemeOf returns "http" or "https" depending on r.TLS.
func schemeOf(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	return "http"
}

// Edge-truncation budgets: keep every per-interaction field bounded so the
// 256MB capacity formula holds even under adversarial requests.
const (
	maxHeadersStored    = 10  // at most 10 header entries
	maxHeaderFieldBytes = 64  // per header key/value
	maxSmallFieldBytes  = 192 // cookie / user-agent / referer
	maxPathQueryBytes   = 256 // path and query
)

// trunc cuts s to at most n bytes.
func trunc(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// flattenHeaders collapses the http.Header multi-map into a flat string→string
// map. When a header has multiple values, they are joined with ", ". Entries
// and per-entry length are capped (10 entries × 64B) to bound memory.
func flattenHeaders(h http.Header) map[string]string {
	out := make(map[string]string, min(len(h), maxHeadersStored))
	for k, v := range h {
		if len(out) >= maxHeadersStored {
			break
		}
		if len(v) == 0 {
			continue
		}
		out[trunc(k, maxHeaderFieldBytes)] = trunc(strings.Join(v, ", "), maxHeaderFieldBytes)
	}
	return out
}

// stripPort removes the :port suffix from a host:port string. Works for both
// IPv4 and IPv6 literals.
func stripPort(h string) string {
	if h == "" {
		return ""
	}
	// IPv6 literal with port: [::1]:8080
	if strings.HasPrefix(h, "[") {
		if i := strings.LastIndex(h, "]"); i >= 0 {
			return h[:i+1]
		}
		return h
	}
	if i := strings.LastIndex(h, ":"); i >= 0 {
		// Make sure it's a port separator and not part of an IPv6 address.
		// A second ":" means this is a bare IPv6 literal.
		if strings.Count(h, ":") > 1 {
			return h
		}
		return h[:i]
	}
	return h
}

// splitHostPort returns the host and port part of an "ip:port" string.
func splitHostPort(addr string) (string, int) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return addr, 0
	}
	var p int
	for i := 0; i < len(port); i++ {
		if port[i] < '0' || port[i] > '9' {
			return host, 0
		}
		p = p*10 + int(port[i]-'0')
	}
	return host, p
}
