package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeTempYAML(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatalf("write yaml: %v", err)
	}
	return p
}

func validYAML() string {
	return `
server:
  dns:
    listen: ":5300"
    protocols: ["udp"]
  http:
    listen: ":8080"
  admin:
    listen: ":8443"
auth:
  jwt_secret: "supersecret-value-1234567890"
  access_ttl: "15m"
  refresh_ttl: "168h"
  bcrypt_cost: 10
storage:
  mode: "memory"
  max_interactions: 1000
  max_per_token: 100
  body_truncate_bytes: 2048
token:
  default_ttl: "24h"
domains:
  - name: "oast.test"
    response_ip: "127.0.0.1"
    txt_payload: "t"
event_bus:
  buffer: 64
  workers: 2
  batch_size: 8
  flush_interval: "10ms"
log:
  level: "debug"
  format: "text"
bootstrap:
  admin_username: "admin"
  admin_password: "pw"
`
}

func TestLoad_OK(t *testing.T) {
	p := writeTempYAML(t, validYAML())
	c, err := Load(p)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.Storage.Mode != "memory" {
		t.Errorf("mode = %q", c.Storage.Mode)
	}
	if c.Auth.AccessTTL != 15*time.Minute {
		t.Errorf("access_ttl = %v", c.Auth.AccessTTL)
	}
	if len(c.Domains) != 1 || c.Domains[0].Name != "oast.test" {
		t.Errorf("domains = %+v", c.Domains)
	}
	if c.Bootstrap.AdminUsername != "admin" {
		t.Errorf("bootstrap user = %q", c.Bootstrap.AdminUsername)
	}
}

func TestLoad_Defaults(t *testing.T) {
	minYAML := strings.Replace(validYAML(),
		"  mode: \"memory\"\n  max_interactions: 1000\n  max_per_token: 100\n  body_truncate_bytes: 2048\n", "", 1)
	p := writeTempYAML(t, minYAML)
	c, err := Load(p)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.Storage.MaxInteractions != 100000 {
		t.Errorf("default max_interactions = %d", c.Storage.MaxInteractions)
	}
	if c.Storage.BodyTruncateBytes != 512 {
		t.Errorf("default body_truncate = %d", c.Storage.BodyTruncateBytes)
	}
}

func TestLoad_Errors(t *testing.T) {
	cases := map[string]string{
		"empty jwt secret":  strings.Replace(validYAML(), "supersecret-value-1234567890", "", 1),
		"short jwt secret":   strings.Replace(validYAML(), "supersecret-value-1234567890", "short", 1),
		"no domains":         strings.Replace(validYAML(), "  - name: \"oast.test\"\n    response_ip: \"127.0.0.1\"\n    txt_payload: \"t\"\n", "", 1),
		"bad storage mode":   strings.Replace(validYAML(), `mode: "memory"`, `mode: "mysql"`, 1),
		"half bootstrap":     strings.Replace(validYAML(), `admin_password: "pw"`, `admin_password: ""`, 1),
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			p := writeTempYAML(t, body)
			if _, err := Load(p); err == nil {
				t.Fatalf("expected error, got nil")
			}
		})
	}
}

func TestLoad_MissingFile(t *testing.T) {
	if _, err := Load("/nonexistent/config.yaml"); err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestValidate_DuplicateDomain(t *testing.T) {
	yaml := strings.Replace(validYAML(),
		"  - name: \"oast.test\"\n    response_ip: \"127.0.0.1\"\n    txt_payload: \"t\"\n",
		"  - name: \"oast.test\"\n    response_ip: \"127.0.0.1\"\n    txt_payload: \"t\"\n  - name: \"oast.test\"\n    response_ip: \"1.2.3.4\"\n", 1)
	p := writeTempYAML(t, yaml)
	if _, err := Load(p); err == nil {
		t.Fatal("expected duplicate-domain error")
	}
}
