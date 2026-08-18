// Package config loads, parses and validates the OAST configuration.
package config

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/v2"
)

// Config is the fully parsed and validated configuration tree.
type Config struct {
	Server    ServerConfig    `koanf:"server"`
	Storage   StorageConfig   `koanf:"storage"`
	Auth      AuthConfig      `koanf:"auth"`
	Token     TokenConfig     `koanf:"token"`
	Domains   []DomainConfig  `koanf:"domains"`
	EventBus  EventBusConfig  `koanf:"event_bus"`
	Log       LogConfig       `koanf:"log"`
	Bootstrap BootstrapConfig `koanf:"bootstrap"`
}

type ServerConfig struct {
	DNS   DNSConfig   `koanf:"dns"`
	HTTP  HTTPConfig   `koanf:"http"`
	Admin AdminConfig  `koanf:"admin"`
}

type DNSConfig struct {
	Listen    string   `koanf:"listen"`
	Protocols []string `koanf:"protocols"`
	// AAAAEnabled controls whether AAAA (IPv6) queries get an answer. Off by
	// default: AAAA queries return NOTIMP so recursive resolvers stop asking
	// and the dashboard stays free of IPv6 noise.
	AAAAEnabled bool `koanf:"aaaa_enabled"`
	// RecordNoise controls whether resolver-meta queries (NS / SOA / any AAAA)
	// are stored as interactions. Off by default so the dashboard only shows
	// real payload traffic (A / TXT / ...).
	RecordNoise bool `koanf:"record_noise"`
}

type HTTPConfig struct {
	Listen         string `koanf:"listen"`
	TLSListen      string `koanf:"tls_listen"`
	TLSCert        string `koanf:"tls_cert"`
	TLSKey         string `koanf:"tls_key"`
	BodyReadLimit  int64  `koanf:"body_read_limit"`
}

type AdminConfig struct {
	Listen      string `koanf:"listen"`
	EnablePprof bool   `koanf:"enable_pprof"`
	// TLS files for the admin server. Both must be set to enable HTTPS;
	// otherwise the admin server serves plain HTTP.
	TLSCert string `koanf:"tls_cert"`
	TLSKey  string `koanf:"tls_key"`
}

type StorageConfig struct {
	Mode              string        `koanf:"mode"` // memory | sqlite
	MaxMemoryMB       int           `koanf:"max_memory_mb"` // GC soft limit (GOMEMLIMIT)
	MaxInteractions   int           `koanf:"max_interactions"`
	MaxPerToken       int           `koanf:"max_per_token"`
	BodyTruncateBytes int           `koanf:"body_truncate_bytes"` // shared by both backends
	RetentionTTL      time.Duration `koanf:"retention_ttl"`
	SQLite            SQLiteConfig  `koanf:"sqlite"`
}

// SQLiteConfig configures the optional file-backed storage backend.
type SQLiteConfig struct {
	Path      string `koanf:"path"`        // relative paths resolve against the executable dir
	MaxFileMB int    `koanf:"max_file_mb"` // hard cap on the db file (SQLITE_FULL backstop)
}

type AuthConfig struct {
	JWTSecret  string        `koanf:"jwt_secret"`
	AccessTTL  time.Duration `koanf:"access_ttl"`
	RefreshTTL time.Duration `koanf:"refresh_ttl"`
	BcryptCost int           `koanf:"bcrypt_cost"`
	// Password enables a simple dnslog-style cookie session gate on the admin
	// UI. Empty = open admin (no auth). No username is required.
	Password string `koanf:"password"`
	// VisitorTTL is the lifetime of the anonymous per-browser cookie used to
	// isolate each visitor's tokens and interactions from everyone else.
	VisitorTTL time.Duration `koanf:"visitor_ttl"`
}

type TokenConfig struct {
	DefaultTTL time.Duration `koanf:"default_ttl"`
}

type DomainConfig struct {
	Name         string   `koanf:"name"`
	ResponseIP   string   `koanf:"response_ip"`
	TXTPayload   string   `koanf:"txt_payload"`
	NSRecords    []string `koanf:"ns_records"`
	SOAPrimaryNS string   `koanf:"soa_primary_ns"`
	SOAEmail     string   `koanf:"soa_email"`
}

type EventBusConfig struct {
	Buffer        int           `koanf:"buffer"`
	Workers       int           `koanf:"workers"`
	BatchSize     int           `koanf:"batch_size"`
	FlushInterval time.Duration `koanf:"flush_interval"`
}

type LogConfig struct {
	Level  string `koanf:"level"`
	Format string `koanf:"format"`
}

type BootstrapConfig struct {
	AdminUsername string `koanf:"admin_username"`
	AdminPassword string `koanf:"admin_password"`
}

// Load reads the YAML config at path, applies defaults and validates.
func Load(path string) (*Config, error) {
	k := koanf.New(".")

	if _, err := os.Stat(path); err != nil {
		return nil, fmt.Errorf("config file %q: %w", path, err)
	}
	if err := k.Load(file.Provider(path), yaml.Parser()); err != nil {
		return nil, fmt.Errorf("load config: %w", err)
	}

	c := &Config{}
	if err := k.Unmarshal("", c); err != nil {
		return nil, fmt.Errorf("unmarshal config: %w", err)
	}

	applyDefaults(c)
	if err := validate(c); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}
	return c, nil
}

func applyDefaults(c *Config) {
	if c.Server.DNS.Listen == "" {
		c.Server.DNS.Listen = ":53"
	}
	if len(c.Server.DNS.Protocols) == 0 {
		c.Server.DNS.Protocols = []string{"udp", "tcp"}
	}
	if c.Server.HTTP.Listen == "" {
		c.Server.HTTP.Listen = ":80"
	}
	if c.Server.HTTP.BodyReadLimit == 0 {
		c.Server.HTTP.BodyReadLimit = 1 << 20 // 1MB
	}
	if c.Server.Admin.Listen == "" {
		c.Server.Admin.Listen = ":8443"
	}
	if c.Storage.Mode == "" {
		c.Storage.Mode = "memory"
	}
	c.Storage.Mode = strings.ToLower(c.Storage.Mode)
	if c.Storage.MaxMemoryMB <= 64 {
		c.Storage.MaxMemoryMB = 256
	}
	if c.Storage.MaxInteractions == 0 {
		c.Storage.MaxInteractions = 100000
	}
	if c.Storage.MaxPerToken == 0 {
		c.Storage.MaxPerToken = 10000
	}
	if c.Storage.BodyTruncateBytes == 0 {
		c.Storage.BodyTruncateBytes = 512
	}
	if c.Storage.SQLite.Path == "" {
		c.Storage.SQLite.Path = "data/oast.db"
	}
	if c.Storage.SQLite.MaxFileMB == 0 {
		c.Storage.SQLite.MaxFileMB = 512
	}
	if c.Storage.RetentionTTL == 0 {
		c.Storage.RetentionTTL = 12 * time.Hour
	}
	if c.Auth.AccessTTL == 0 {
		c.Auth.AccessTTL = 15 * time.Minute
	}
	if c.Auth.RefreshTTL == 0 {
		c.Auth.RefreshTTL = 168 * time.Hour
	}
	if c.Auth.VisitorTTL == 0 {
		c.Auth.VisitorTTL = 168 * time.Hour
	}
	if c.Auth.BcryptCost == 0 {
		c.Auth.BcryptCost = 12
	}
	if c.Token.DefaultTTL == 0 {
		c.Token.DefaultTTL = 168 * time.Hour
	}
	if c.EventBus.Buffer == 0 {
		c.EventBus.Buffer = 4096
	}
	if c.EventBus.Workers == 0 {
		c.EventBus.Workers = 4
	}
	if c.EventBus.BatchSize == 0 {
		c.EventBus.BatchSize = 64
	}
	if c.EventBus.FlushInterval == 0 {
		c.EventBus.FlushInterval = 50 * time.Millisecond
	}
	if c.Log.Level == "" {
		c.Log.Level = "info"
	}
	if c.Log.Format == "" {
		c.Log.Format = "json"
	}
}

func validate(c *Config) error {
	if c.Auth.JWTSecret == "" {
		return fmt.Errorf("auth.jwt_secret must not be empty")
	}
	if len(c.Auth.JWTSecret) < 16 {
		return fmt.Errorf("auth.jwt_secret too short (need >=16 chars)")
	}
	switch c.Storage.Mode {
	case "memory":
		// ok
	case "sqlite":
		if c.Storage.SQLite.Path == "" {
			return fmt.Errorf("storage.sqlite.path is required when mode=sqlite")
		}
	default:
		return fmt.Errorf("storage.mode must be memory or sqlite, got %q", c.Storage.Mode)
	}
	if c.Auth.BcryptCost < 4 || c.Auth.BcryptCost > 31 {
		return fmt.Errorf("auth.bcrypt_cost must be in [4,31]")
	}
	if c.Storage.RetentionTTL < time.Minute {
		return fmt.Errorf("storage.retention_ttl too small (need >=1m)")
	}
	if len(c.Domains) == 0 {
		return fmt.Errorf("at least one domain must be configured")
	}
	seen := map[string]bool{}
	for i, d := range c.Domains {
		if d.Name == "" {
			return fmt.Errorf("domains[%d].name empty", i)
		}
		dn := strings.ToLower(d.Name)
		if seen[dn] {
			return fmt.Errorf("duplicate domain %q", d.Name)
		}
		seen[dn] = true
		if d.ResponseIP == "" {
			return fmt.Errorf("domains[%d].response_ip empty", i)
		}
	}
	// bootstrap is optional: when both fields are empty we skip admin user
	// creation. The admin UI may still be gated by auth.password (cookie session).
	if (c.Bootstrap.AdminUsername == "") != (c.Bootstrap.AdminPassword == "") {
		return fmt.Errorf("bootstrap.admin_username and admin_password must be both set or both empty")
	}
	if c.EventBus.Buffer < 16 {
		return fmt.Errorf("event_bus.buffer too small")
	}
	if c.EventBus.Workers < 1 {
		return fmt.Errorf("event_bus.workers must be >=1")
	}
	return nil
}
