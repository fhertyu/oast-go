// Package storage defines the in-memory data models and Store for the OAST platform.
//
// All data lives in process memory; nothing is persisted. A restart clears every
// record. The models here are shared between the Store, the Event Bus and the
// API layer.
package storage

import "time"

// Role is the RBAC role assigned to a user.
type Role string

const (
	RoleAdmin   Role = "admin"
	RoleAuditor Role = "auditor"
	RoleViewer  Role = "viewer"
)

// UserStatus describes account lifecycle.
type UserStatus string

const (
	UserActive   UserStatus = "active"
	UserDisabled UserStatus = "disabled"
)

// TokenStatus describes the lifecycle of a callback token.
type TokenStatus string

const (
	TokenActive  TokenStatus = "active"
	TokenExpired TokenStatus = "expired"
	TokenRevoked TokenStatus = "revoked"
)

// InteractionType discriminates DNS vs HTTP events.
type InteractionType string

const (
	InteractionDNS  InteractionType = "dns"
	InteractionHTTP InteractionType = "http"
)

// User is an admin-console account.
type User struct {
	ID           int64     `json:"id"`
	Username     string    `json:"username"`
	Email        string    `json:"email,omitempty"`
	PasswordHash string    `json:"-"` // never serialized
	Role         Role      `json:"role"`
	Status       UserStatus `json:"status"`
	LastLoginAt  time.Time `json:"last_login_at,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// Project groups tokens and interactions for a tenant.
type Project struct {
	ID          int64     `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
	OwnerID     int64     `json:"owner_id"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// ProjectMember is a many-to-many link with an optional per-project role override.
type ProjectMember struct {
	ProjectID int64     `json:"project_id"`
	UserID    int64     `json:"user_id"`
	Role      Role      `json:"role,omitempty"` // overrides user's global role within project scope
	JoinedAt  time.Time `json:"joined_at"`
}

// Domain is an OAST zone bound to one or more tokens.
type Domain struct {
	ID           int64    `json:"id"`
	Name         string   `json:"name"` // e.g. oast.example.com
	NSRecords    []string `json:"ns_records,omitempty"`
	ResponseIP   string   `json:"response_ip"`
	TXTPayload   string   `json:"txt_payload,omitempty"`
	SOAPrimaryNS string   `json:"soa_primary_ns,omitempty"`
	SOAEmail     string   `json:"soa_email,omitempty"`
	Status       string   `json:"status"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// Token is the random subdomain string bound to a user/project/domain.
type Token struct {
	ID        int64        `json:"id"`
	Value     string       `json:"value"` // 8-char base32url, the subdomain label
	DomainID  int64        `json:"domain_id"`
	UserID    int64        `json:"user_id"`
	ProjectID int64        `json:"project_id"`
	Status    TokenStatus  `json:"status"`
	ExpiresAt time.Time    `json:"expires_at"`
	CreatedAt time.Time    `json:"created_at"`
	RevokedAt *time.Time   `json:"revoked_at,omitempty"`
	Note      string       `json:"note,omitempty"`
}

// Interaction is a single OOB callback event (DNS query or HTTP request).
type Interaction struct {
	ID          int64            `json:"id"`
	TokenID     int64            `json:"token_id"`      // 0 for wildcard events
	TokenValue  string           `json:"token_value"`   // denormalized, survives token revoke
	DomainID    int64            `json:"domain_id"`
	Type        InteractionType  `json:"type"`
	SubType     string           `json:"sub_type,omitempty"` // qtype | http method
	Protocol    string           `json:"protocol,omitempty"` // udp/tcp | http/https
	SrcIP       string           `json:"src_ip"`
	SrcPort     int              `json:"src_port,omitempty"`
	// HTTP-specific
	Method     string            `json:"method,omitempty"`
	Path       string            `json:"path,omitempty"`
	Query      string            `json:"query,omitempty"`
	Headers    map[string]string `json:"headers,omitempty"`
	Cookie     string            `json:"cookie,omitempty"`
	UserAgent  string            `json:"user_agent,omitempty"`
	Referer    string            `json:"referer,omitempty"`
	Body       string            `json:"body,omitempty"` // truncated to body_truncate_bytes
	// DNS-specific
	QName string `json:"qname,omitempty"`
	QType string `json:"qtype,omitempty"`
	// Labels holds the full token-prefix labels (left-to-right), including any
	// client-exfiltrated data labels that precede the token (data.token.domain).
	Labels []string `json:"labels,omitempty"`
	// Common
	RawRequest string    `json:"raw_request,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
}

// LogEntry is an audit record.
type LogEntry struct {
	ID         int64     `json:"id"`
	UserID     int64     `json:"user_id,omitempty"` // 0 for system actions
	Action     string    `json:"action"`           // e.g. token.create
	TargetType string   `json:"target_type,omitempty"`
	TargetID   string   `json:"target_id,omitempty"`
	Detail     string   `json:"detail,omitempty"` // JSON string
	IP         string   `json:"ip,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
}

// RefreshToken stores a hashed refresh token for revocation tracking.
type RefreshToken struct {
	ID        int64      `json:"id"`
	UserID    int64      `json:"user_id"`
	TokenHash string     `json:"-"` // sha256 hex, never serialized
	ExpiresAt time.Time  `json:"expires_at"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
	IP        string     `json:"ip,omitempty"`
}

// InteractionFilter captures query parameters for the interactions API.
type InteractionFilter struct {
	TokenValue string           // exact match (single token)
	TokenValues []string        // ownership scope: only tokens in this set are visible
	Type       InteractionType  // dns|http, empty = any
	SrcIP      string           // exact match
	DomainID   int64            // 0 = any
	StartTime  *time.Time       // inclusive
	EndTime    *time.Time       // inclusive
	Limit      int              // page size, capped server-side
	Offset     int              // pagination
	OrderDesc  bool             // default true (newest first)
}
