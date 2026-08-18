package config

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

// DefaultYAML returns a starter config with freshly generated random secrets.
// It is written to disk on first run when no config file is found.
func DefaultYAML() (string, error) {
	secret, err := randHex(32) // 256-bit
	if err != nil {
		return "", fmt.Errorf("gen jwt secret: %w", err)
	}
	return fmt.Sprintf(`# OAST default config — auto-generated on first run.
# REVIEW EVERY FIELD, especially domains / response_ip / jwt_secret / password.
# 默认使用非特权端口方便本地测试；生产部署请改用 :53 / :80 / :443。

server:
  dns:
    # 生产用 :53（需要 root）；本地测试用 5300
    listen: ":5300"
    protocols: ["udp", "tcp"]
    # AAAA（IPv6）查询是否应答：默认关闭，返回 NOTIMP，减少 IPv6 噪音
    aaaa_enabled: false
    # 是否记录 NS/SOA 等解析器元查询：默认关闭，列表只显示真实回调
    record_noise: false
  http:
    # 生产用 :80；本地测试用 8080
    listen: ":8080"
    tls_listen: ":4443"
    tls_cert: ""
    tls_key: ""
    body_read_limit: 1048576
  admin:
    # 后台端口，默认 http（不配 tls_cert/tls_key 就是 http）
    listen: ":8443"
    enable_pprof: false
    tls_cert: ""
    tls_key: ""

storage:
  mode: "memory"               # memory | sqlite
  # sqlite 模式配置（mode=sqlite 时生效）
  sqlite:
    path: "data/oast.db"       # 相对路径基于可执行文件目录
    max_file_mb: 512           # db 文件硬上限（写满返回 SQLITE_FULL，进程不死）
  max_memory_mb: 256           # 进程内存软上限（GOMEMLIMIT）
  max_interactions: 100000     # memory 模式全局条数上限（FIFO 淘汰）
  max_per_token: 10000
  body_truncate_bytes: 512     # 采集边缘截断（两模式共用）
  # 交互记录保留时长，超过自动清理（12h）
  retention_ttl: "12h"

auth:
  jwt_secret: %q
  access_ttl: "15m"
  refresh_ttl: "168h"
  bcrypt_cost: 12
  # dnslog 风格的可选密码门（只密码，不要用户名）
  # 留空 = 后台完全开放（适合内网/受信网络）
  # 设置一个字符串 = 访问后台需要先输入密码
  password: ""
  # 匿名访客隔离 cookie 有效期（每个浏览器只能看到自己创建的 token 和回调）
  # 到期后访客身份重置，历史 token 不再可见
  visitor_ttl: "168h"

token:
  default_ttl: "168h"

domains:
  - name: "oast.example.com"
    response_ip: "127.0.0.1"
    txt_payload: "oast-v1"
    ns_records: ["ns1.example.com", "ns2.example.com"]
    soa_primary_ns: "ns1.example.com"
    soa_email: "admin.example.com"

event_bus:
  buffer: 4096
  workers: 4
  batch_size: 64
  flush_interval: "50ms"

log:
  level: "info"
  format: "text"

# dnslog 模式下不需要传统 admin 用户；留空即可
bootstrap:
  admin_username: ""
  admin_password: ""
`, secret), nil
}

// randHex returns n random bytes as a lowercase hex string (2n chars).
func randHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
