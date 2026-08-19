// Command oast runs the OAST platform: DNS + HTTP OOB callback collector
// with a cookie-gated admin dashboard. This entrypoint wires the in-memory
// store, token manager, event bus, domain manager, the DNS / HTTP collectors
// and the admin HTTP API.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"strings"
	"syscall"
	"time"

	"github.com/oast/oast/internal/api"
	"github.com/oast/oast/internal/auth"
	"github.com/oast/oast/internal/config"
	"github.com/oast/oast/internal/domain"
	"github.com/oast/oast/internal/interaction"
	"github.com/oast/oast/internal/storage"
	"github.com/oast/oast/internal/token"
	dnssrv "github.com/oast/oast/pkg/dns"
	"github.com/oast/oast/pkg/httpserver"
)

// version is set via -ldflags at build time.
var version = "dev"

func main() {
	configPath := flag.String("config", "", "path to config file (default: <exec_dir>/config.yaml; auto-created on first run)")
	initConfig := flag.Bool("init", false, "write a default config next to the binary (with random secrets) and exit")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	printBanner()

	if *showVersion {
		fmt.Println("oast", version)
		return
	}

	if *initConfig {
		if err := writeDefaultConfig(*configPath); err != nil {
			fmt.Fprintf(os.Stderr, "init: %v\n", err)
			os.Exit(1)
		}
		return
	}

	path, err := resolveConfig(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config: %v\n", err)
		os.Exit(2)
	}

	cfg, err := config.Load(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load config %q: %v\n", path, err)
		os.Exit(2)
	}

	log := newLogger(cfg.Log)

	// GC soft limit (GOMEMLIMIT): keeps RSS near max_memory_mb - 32MB headroom.
	// Near the limit the GC turns aggressive — slow, but the process survives.
	if cfg.Storage.MaxMemoryMB > 64 {
		_ = debug.SetMemoryLimit(int64(cfg.Storage.MaxMemoryMB-32) << 20)
	}

	log.Info("starting oast", "version", version, "storage", cfg.Storage.Mode, "config", path)

	rootCtx, rootCancel := context.WithCancel(context.Background())

	// Wire components
	// Storage backend: memory (default) or sqlite (file-backed).
	var store storage.Store
	switch strings.ToLower(cfg.Storage.Mode) {
	case "sqlite":
		dbPath := cfg.Storage.SQLite.Path
		if !filepath.IsAbs(dbPath) {
			if execD, err := execDir(); err == nil && execD != "" {
				dbPath = filepath.Join(execD, dbPath)
			}
		}
		st, err := storage.NewSQLiteStore(dbPath,
			cfg.Storage.MaxInteractions, cfg.Storage.MaxPerToken,
			cfg.Storage.BodyTruncateBytes, cfg.Storage.SQLite.MaxFileMB, log)
		if err != nil {
			log.Error("init sqlite storage", "err", err)
			os.Exit(1)
		}
		store = st
		log.Info("storage ready", "mode", "sqlite", "path", dbPath,
			"max_file_mb", cfg.Storage.SQLite.MaxFileMB)
	default:
		store = storage.NewMemoryStore(cfg.Storage.MaxInteractions,
			cfg.Storage.MaxPerToken, cfg.Storage.BodyTruncateBytes)
		log.Info("storage ready", "mode", "memory",
			"cap", cfg.Storage.MaxInteractions, "retention", cfg.Storage.RetentionTTL.String())
	}

	domMgr := bootstrapDomains(rootCtx, log, cfg, store)
	tokenMgr := token.NewManager(store, cfg.Token.DefaultTTL)
	// JWT/authenticator are kept for the legacy username/password bootstrap path;
	// the dnslog-style admin UI is gated by auth.password (cookie session).
	_ = auth.NewJWT(cfg.Auth.JWTSecret, cfg.Auth.AccessTTL, cfg.Auth.RefreshTTL)

	bus := interaction.New(rootCtx, store,
		cfg.EventBus.Buffer, cfg.EventBus.Workers, cfg.EventBus.BatchSize,
		cfg.EventBus.FlushInterval, log)
	bus.Start(cfg.EventBus.Workers)
	log.Info("event bus started",
		"buffer", cfg.EventBus.Buffer, "workers", cfg.EventBus.Workers,
		"batch", cfg.EventBus.BatchSize, "flush", cfg.EventBus.FlushInterval)

	// Optional: create legacy admin user when bootstrap.admin_username is set.
	if cfg.Bootstrap.AdminUsername != "" && cfg.Bootstrap.AdminPassword != "" {
		bootstrapAdmin(rootCtx, log, cfg, store)
	}

	// Background sweepers
	go runTokenSweeper(rootCtx, log, tokenMgr, store, cfg.Storage.RetentionTTL)
	go runRefreshSweeper(rootCtx, log, store)
	go runRetentionSweeper(rootCtx, log, store, cfg.Storage.RetentionTTL)

	// Start the DNS collector (Phase 4).
	dnsSrv := dnssrv.New(cfg.Server.DNS, domMgr, bus, store, log)
	if err := dnsSrv.Start(); err != nil {
		log.Error("dns server start failed", "err", err)
		os.Exit(1)
	}

	// Start the HTTP callback collector (Phase 5).
	httpSrv := httpserver.New(cfg.Server.HTTP, domMgr, bus, store, cfg.Storage.BodyTruncateBytes, log)
	if err := httpSrv.Start(); err != nil {
		log.Error("http server start failed", "err", err)
		os.Exit(1)
	}

	// Start the admin HTTP API + dashboard (Phase 6).
	apiSrv := api.New(*cfg, store, tokenMgr, log)
	if err := apiSrv.Start(); err != nil {
		log.Error("admin server start failed", "err", err)
		os.Exit(1)
	}

	// Ordered shutdown: collectors MUST stop (no new Submit calls) BEFORE
	// bus.Stop closes the channel — otherwise a late Submit panics on
	// send-to-closed-channel.
	defer func() {
		dnsSrv.Shutdown()
		httpSrv.Shutdown()
		apiSrv.Shutdown()
		bus.Stop(10 * time.Second)
		log.Info("event bus stopped", "total", bus.Total(), "dropped", bus.Dropped())
		rootCancel()
		_ = store.Close()
		log.Info("oast stopped")
	}()

	adminURL := adminURL(cfg)
	log.Info("oast ready",
		"dns_listen", cfg.Server.DNS.Listen,
		"http_listen", cfg.Server.HTTP.Listen,
		"admin_listen", cfg.Server.Admin.Listen,
		"admin_url", adminURL,
		"domains", len(cfg.Domains),
		"retention", cfg.Storage.RetentionTTL.String(),
		"auth", cfg.Auth.Password != "")
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "  Dashboard:", adminURL)
	fmt.Fprintln(os.Stderr)

	// Wait for shutdown signal; all cleanup is performed by the ordered
	// shutdown chain registered above.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigCh
	log.Info("shutdown signal received", "signal", sig.String())
}

// adminURL returns the public URL of the admin dashboard.
func adminURL(cfg *config.Config) string {
	scheme := "http"
	if cfg.Server.Admin.TLSCert != "" && cfg.Server.Admin.TLSKey != "" {
		scheme = "https"
	}
	host := cfg.Server.Admin.Listen
	if host == "" {
		host = ":8443"
	}
	// Trim leading ":" so ":8443" → "localhost:8443"
	if strings.HasPrefix(host, ":") {
		host = "localhost" + host
	}
	return scheme + "://" + host + "/"
}

func newLogger(c config.LogConfig) *slog.Logger {
	var level slog.Level
	switch c.Level {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}
	opts := &slog.HandlerOptions{Level: level}
	var h slog.Handler
	if c.Format == "text" {
		h = slog.NewTextHandler(os.Stdout, opts)
	} else {
		h = slog.NewJSONHandler(os.Stdout, opts)
	}
	return slog.New(h)
}

func bootstrapDomains(ctx context.Context, log *slog.Logger, cfg *config.Config, store storage.Store) *domain.Manager {
	mgr := domain.NewManager()
	for _, dc := range cfg.Domains {
		d := &storage.Domain{
			Name:         dc.Name,
			ResponseIP:   dc.ResponseIP,
			TXTPayload:   dc.TXTPayload,
			NSRecords:    dc.NSRecords,
			SOAPrimaryNS: dc.SOAPrimaryNS,
			SOAEmail:     dc.SOAEmail,
		}
		if err := store.CreateDomain(ctx, d); err != nil {
			// Domain already exists (e.g. SQLite restart): load it from
			// the store so the in-memory trie stays in sync.
			existing, err2 := store.GetDomainByName(ctx, dc.Name)
			if err2 != nil {
				log.Error("domain bootstrap failed", "name", dc.Name,
					"create_err", err, "lookup_err", err2)
				continue
			}
			d = existing
		}
		mgr.Add(d)
		log.Info("domain registered", "name", d.Name, "ip", d.ResponseIP)
	}
	return mgr
}

func bootstrapAdmin(ctx context.Context, log *slog.Logger, cfg *config.Config, store storage.Store) {
	users, err := store.ListUsers(ctx)
	if err != nil {
		log.Error("list users during bootstrap", "err", err)
		return
	}
	if len(users) > 0 {
		return
	}
	hash, err := auth.HashPassword(cfg.Bootstrap.AdminPassword, cfg.Auth.BcryptCost)
	if err != nil {
		log.Error("hash bootstrap password", "err", err)
		return
	}
	u := &storage.User{
		Username:     cfg.Bootstrap.AdminUsername,
		PasswordHash: hash,
		Role:         storage.RoleAdmin,
		Status:       storage.UserActive,
	}
	if err := store.CreateUser(ctx, u); err != nil {
		log.Error("create bootstrap admin", "err", err)
		return
	}
	log.Warn("bootstrap admin created; CHANGE PASSWORD IMMEDIATELY",
		"username", u.Username)
}

// runTokenSweeper marks expired tokens, then hard-deletes tokens that
// expired more than grace ago (interactions survive via the denormalized
// TokenValue).
func runTokenSweeper(ctx context.Context, log *slog.Logger, m *token.Manager, s storage.Store, grace time.Duration) {
	t := time.NewTicker(10 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if n, err := m.SweepExpired(ctx); err != nil {
				log.Error("token sweep", "err", err)
			} else if n > 0 {
				log.Info("token sweep", "expired", n)
			}
			if n, err := s.DeletePurgedTokens(ctx, time.Now(), grace); err != nil {
				log.Error("token purge", "err", err)
			} else if n > 0 {
				log.Info("token purge", "deleted", n)
			}
		}
	}
}

func runRefreshSweeper(ctx context.Context, log *slog.Logger, s storage.Store) {
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if n, err := s.DeleteExpiredRefreshTokens(ctx, time.Now()); err != nil {
				log.Error("refresh sweep", "err", err)
			} else if n > 0 {
				log.Info("refresh sweep", "deleted", n)
			}
		}
	}
}

// runRetentionSweeper deletes interactions older than retentionTTL. Runs every
// 5 minutes; the first sweep starts after 5 minutes so we don't churn on boot.
func runRetentionSweeper(ctx context.Context, log *slog.Logger, s storage.Store, retention time.Duration) {
	if retention <= 0 {
		return
	}
	t := time.NewTicker(5 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			cutoff := time.Now().Add(-retention)
			if n, err := s.DeleteOldInteractions(ctx, cutoff); err != nil {
				log.Error("retention sweep", "err", err)
			} else if n > 0 {
				log.Info("retention sweep", "deleted", n, "older_than", cutoff.Format(time.RFC3339))
			}
		}
	}
}

// resolveConfig finds the config file next to the binary. If the file does not
// exist, a default template is auto-created there (with random secrets).
//
// Behavior:
//   - If -config is given explicitly, that path is used as-is; a missing file
//     is an error (no auto-create for an explicit, user-provided path).
//   - Otherwise the config is resolved as <exec_dir>/config.yaml. When it does
//     not yet exist, a default template is written to that location and then
//     loaded. The user is warned to review the generated secrets/domains.
func resolveConfig(explicit string) (string, error) {
	if explicit != "" {
		if !fileExists(explicit) {
			return "", fmt.Errorf("config file not found: %s", explicit)
		}
		return explicit, nil
	}

	execD, err := execDir()
	if err != nil || execD == "" {
		return "", fmt.Errorf("cannot locate executable directory: %w", err)
	}
	target := filepath.Join(execD, "config.yaml")

	if !fileExists(target) {
		fmt.Fprintf(os.Stderr, "no config next to binary; creating default template at %s\n", target)
		if err := writeDefaultConfig(target); err != nil {
			return "", fmt.Errorf("auto-create config: %w", err)
		}
		fmt.Fprintf(os.Stderr, "review jwt_secret / admin_password / domains in %s before production use\n", target)
	}
	return target, nil
}

// writeDefaultConfig writes a starter config (random secrets) to outPath, or
// <exec_dir>/config.yaml when outPath is empty. Used by `oast -init` and by the
// auto-create-on-first-run path. Refuses to overwrite an existing file.
func writeDefaultConfig(outPath string) error {
	if outPath == "" {
		execD, err := execDir()
		if err != nil || execD == "" {
			return fmt.Errorf("cannot locate executable directory: %w", err)
		}
		outPath = filepath.Join(execD, "config.yaml")
	}
	body, err := config.DefaultYAML()
	if err != nil {
		return fmt.Errorf("render default config: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}
	if fileExists(outPath) {
		return fmt.Errorf("refusing to overwrite existing config: %s", outPath)
	}
	if err := os.WriteFile(outPath, []byte(body), 0o600); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	fmt.Fprintf(os.Stderr, "wrote default config to %s (review jwt_secret / admin_password / domains before running)\n", outPath)
	return nil
}

// printBanner writes a short Powered-by header to stderr at startup.
func printBanner() {
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "  ___  ___ ___")
	fmt.Fprintln(os.Stderr, " / _ \\/ __| __|")
	fmt.Fprintln(os.Stderr, "| (_) \\__ \\ _|")
	fmt.Fprintln(os.Stderr, " \\___/|___/___|")
	fmt.Fprintln(os.Stderr, "Powered by fhertyu  |  version: "+version)
	fmt.Fprintln(os.Stderr)
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func execDir() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	resolved, err := filepath.EvalSymlinks(exe)
	if err != nil {
		resolved = exe
	}
	return filepath.Dir(resolved), nil
}
