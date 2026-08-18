package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite" // pure-Go SQLite driver, keeps CGO_ENABLED=0 cross-compilation
)

// sqliteSchema mirrors the memory models 1:1. Idempotent (IF NOT EXISTS) so
// reopening an existing database is safe.
const sqliteSchema = `
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT    NOT NULL UNIQUE,
    email         TEXT    NOT NULL DEFAULT '',
    password_hash TEXT    NOT NULL DEFAULT '',
    role          TEXT    NOT NULL DEFAULT 'viewer',
    status        TEXT    NOT NULL DEFAULT 'active',
    last_login_at INTEGER NOT NULL DEFAULT 0,
    created_at    INTEGER NOT NULL,
    updated_at    INTEGER NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email ON users(email) WHERE email <> '';

CREATE TABLE IF NOT EXISTS projects (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT    NOT NULL,
    description TEXT    NOT NULL DEFAULT '',
    owner_id    INTEGER NOT NULL DEFAULT 0,
    created_at  INTEGER NOT NULL,
    updated_at  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS project_members (
    project_id INTEGER NOT NULL,
    user_id    INTEGER NOT NULL,
    role       TEXT    NOT NULL DEFAULT '',
    joined_at  INTEGER NOT NULL,
    PRIMARY KEY (project_id, user_id)
);

CREATE TABLE IF NOT EXISTS domains (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    name           TEXT    NOT NULL UNIQUE,
    response_ip    TEXT    NOT NULL DEFAULT '',
    txt_payload    TEXT    NOT NULL DEFAULT '',
    ns_records     TEXT    NOT NULL DEFAULT '[]',
    soa_primary_ns TEXT    NOT NULL DEFAULT '',
    soa_email      TEXT    NOT NULL DEFAULT '',
    status         TEXT    NOT NULL DEFAULT 'active',
    created_at     INTEGER NOT NULL,
    updated_at     INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS tokens (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    value      TEXT    NOT NULL UNIQUE,
    domain_id  INTEGER NOT NULL DEFAULT 0,
    user_id    INTEGER NOT NULL DEFAULT 0,
    project_id INTEGER NOT NULL DEFAULT 0,
    note       TEXT    NOT NULL DEFAULT '',
    status     TEXT    NOT NULL DEFAULT 'active',
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    revoked_at INTEGER
);
CREATE INDEX IF NOT EXISTS idx_tokens_user ON tokens(user_id);

CREATE TABLE IF NOT EXISTS interactions (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    token_value TEXT    NOT NULL DEFAULT '',
    token_id    INTEGER NOT NULL DEFAULT 0,
    domain_id   INTEGER NOT NULL DEFAULT 0,
    type        TEXT    NOT NULL,
    sub_type    TEXT    NOT NULL DEFAULT '',
    protocol    TEXT    NOT NULL DEFAULT '',
    src_ip      TEXT    NOT NULL DEFAULT '',
    src_port    INTEGER NOT NULL DEFAULT 0,
    method      TEXT    NOT NULL DEFAULT '',
    path        TEXT    NOT NULL DEFAULT '',
    query       TEXT    NOT NULL DEFAULT '',
    headers     TEXT    NOT NULL DEFAULT '{}',
    cookie      TEXT    NOT NULL DEFAULT '',
    user_agent  TEXT    NOT NULL DEFAULT '',
    referer     TEXT    NOT NULL DEFAULT '',
    body        TEXT    NOT NULL DEFAULT '',
    qname       TEXT    NOT NULL DEFAULT '',
    qtype       TEXT    NOT NULL DEFAULT '',
    labels      TEXT    NOT NULL DEFAULT '[]',
    raw_request TEXT    NOT NULL DEFAULT '',
    created_at  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_int_token_created ON interactions(token_value, id DESC);
CREATE INDEX IF NOT EXISTS idx_int_created ON interactions(id DESC);

CREATE TABLE IF NOT EXISTS logs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL DEFAULT 0,
    action      TEXT    NOT NULL,
    target_type TEXT    NOT NULL DEFAULT '',
    target_id   TEXT    NOT NULL DEFAULT '',
    detail      TEXT    NOT NULL DEFAULT '',
    ip          TEXT    NOT NULL DEFAULT '',
    created_at  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS refresh_tokens (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL DEFAULT 0,
    token_hash TEXT    NOT NULL UNIQUE,
    expires_at INTEGER NOT NULL,
    revoked_at INTEGER,
    created_at INTEGER NOT NULL,
    ip         TEXT    NOT NULL DEFAULT ''
);
`

const interactionCols = `id, token_value, token_id, domain_id, type, sub_type, protocol, src_ip, src_port, method, path, query, headers, cookie, user_agent, referer, body, qname, qtype, labels, raw_request, created_at`

const insertInteractionSQL = `INSERT INTO interactions
    (token_value, token_id, domain_id, type, sub_type, protocol, src_ip, src_port,
     method, path, query, headers, cookie, user_agent, referer, body,
     qname, qtype, labels, raw_request, created_at)
VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`

// SQLiteStore is the file-backed Store implementation. Semantics mirror
// MemoryStore (FIFO eviction, per-token caps, fail-closed ownership scope);
// data survives restarts.
type SQLiteStore struct {
	db            *sql.DB
	log           *slog.Logger
	bodyTruncate  int
	maxInteractions int
	maxPerToken   int
}

// NewSQLiteStore opens (or creates) the database at path. Pragmas go through
// the DSN; auto_vacuum/max_page_count must run before the schema is created.
func NewSQLiteStore(path string, maxInteractions, maxPerToken, bodyTruncate, maxFileMB int, log *slog.Logger) (*SQLiteStore, error) {
	if maxInteractions <= 0 {
		maxInteractions = 100000
	}
	if maxPerToken <= 0 {
		maxPerToken = 10000
	}
	if bodyTruncate <= 0 {
		bodyTruncate = 512
	}
	if maxFileMB <= 0 {
		maxFileMB = 512
	}
	if log == nil {
		log = slog.Default()
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("sqlite mkdir: %w", err)
	}
	// All pragmas in the DSN: busy_timeout rides out write contention, WAL
	// allows concurrent readers, NORMAL sync is safe under WAL, and the page
	// cache is capped at 32MB so RSS stays modest.
	dsn := "file:" + filepath.ToSlash(path) +
		"?_pragma=busy_timeout(5000)" +
		"&_pragma=journal_mode(WAL)" +
		"&_pragma=synchronous(NORMAL)" +
		"&_pragma=cache_size(-32768)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("sqlite open: %w", err)
	}
	db.SetMaxOpenConns(4) // WAL: concurrent readers, single serialized writer

	s := &SQLiteStore{
		db:              db,
		log:             log,
		bodyTruncate:    bodyTruncate,
		maxInteractions: maxInteractions,
		maxPerToken:     maxPerToken,
	}
	if err := s.init(maxFileMB); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

func (s *SQLiteStore) init(maxFileMB int) error {
	// auto_vacuum must be set before any table exists; on a legacy database
	// it only takes effect after a VACUUM, which incremental_vacuum replaces.
	if _, err := s.db.Exec(`PRAGMA auto_vacuum = INCREMENTAL`); err != nil {
		return fmt.Errorf("sqlite auto_vacuum: %w", err)
	}
	// File-level hard cap: writes past max_file_mb fail with SQLITE_FULL;
	// the batch layer logs the error and the process keeps running.
	if _, err := s.db.Exec(fmt.Sprintf(`PRAGMA max_page_count = %d`, maxFileMB*256)); err != nil {
		return fmt.Errorf("sqlite max_page_count: %w", err)
	}
	if _, err := s.db.Exec(sqliteSchema); err != nil {
		return fmt.Errorf("sqlite schema: %w", err)
	}
	return nil
}

// Close closes the underlying database.
func (s *SQLiteStore) Close() error { return s.db.Close() }

// maintenance shrinks the WAL and returns freed pages to the OS. Runs after
// retention purges; errors are non-fatal by design.
func (s *SQLiteStore) maintenance() {
	_, _ = s.db.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`)
	_, _ = s.db.Exec(`PRAGMA incremental_vacuum`)
}

// ---- helpers ----

func msToTime(ms int64) time.Time {
	if ms == 0 {
		return time.Time{}
	}
	return time.UnixMilli(ms).UTC()
}

func ms(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UnixMilli()
}

func jsonOrNull(v any, fallback string) string {
	if v == nil {
		return fallback
	}
	b, err := json.Marshal(v)
	if err != nil {
		return fallback
	}
	return string(b)
}

// ---- Users ----

func (s *SQLiteStore) CreateUser(ctx context.Context, u *User) error {
	if u.Username == "" {
		return ErrValidationT("username required")
	}
	var n int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(1) FROM users WHERE username = ?`, u.Username).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return ErrConflictT("username already exists")
	}
	if u.Email != "" {
		if err := s.db.QueryRowContext(ctx, `SELECT COUNT(1) FROM users WHERE email = ?`, u.Email).Scan(&n); err != nil {
			return err
		}
		if n > 0 {
			return ErrConflictT("email already exists")
		}
	}
	if u.Role == "" {
		u.Role = RoleViewer
	}
	if u.Status == "" {
		u.Status = UserActive
	}
	now := time.Now().UTC()
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO users (username, email, password_hash, role, status, last_login_at, created_at, updated_at)
		 VALUES (?,?,?,?,?,?,?,?)`,
		u.Username, u.Email, u.PasswordHash, string(u.Role), string(u.Status), ms(u.LastLoginAt), ms(now), ms(now))
	if err != nil {
		return err
	}
	u.ID, _ = res.LastInsertId()
	u.CreatedAt, u.UpdatedAt = now, now
	return nil
}

func scanUser(scan func(dest ...any) error) (*User, error) {
	var (
		u          User
		role       string
		status     string
		lastLogin  int64
		created    int64
		updated    int64
	)
	if err := scan(&u.ID, &u.Username, &u.Email, &u.PasswordHash, &role, &status, &lastLogin, &created, &updated); err != nil {
		return nil, err
	}
	u.Role, u.Status = Role(role), UserStatus(status)
	u.LastLoginAt, u.CreatedAt, u.UpdatedAt = msToTime(lastLogin), msToTime(created), msToTime(updated)
	return &u, nil
}

const userCols = `id, username, email, password_hash, role, status, last_login_at, created_at, updated_at`

func (s *SQLiteStore) GetUser(ctx context.Context, id int64) (*User, error) {
	u, err := scanUser(s.db.QueryRowContext(ctx, `SELECT `+userCols+` FROM users WHERE id = ?`, id).Scan)
	if errorsIsNoRows(err) {
		return nil, ErrNotFoundT("user")
	}
	return u, err
}

func (s *SQLiteStore) GetUserByUsername(ctx context.Context, username string) (*User, error) {
	u, err := scanUser(s.db.QueryRowContext(ctx, `SELECT `+userCols+` FROM users WHERE username = ?`, username).Scan)
	if errorsIsNoRows(err) {
		return nil, ErrNotFoundT("user")
	}
	return u, err
}

func (s *SQLiteStore) UpdateUser(ctx context.Context, u *User) error {
	ex, err := s.GetUser(ctx, u.ID)
	if err != nil {
		return err
	}
	var n int
	if u.Username != ex.Username {
		if err := s.db.QueryRowContext(ctx, `SELECT COUNT(1) FROM users WHERE username = ? AND id <> ?`, u.Username, u.ID).Scan(&n); err != nil {
			return err
		}
		if n > 0 {
			return ErrConflictT("username already exists")
		}
	}
	if u.Email != "" && u.Email != ex.Email {
		if err := s.db.QueryRowContext(ctx, `SELECT COUNT(1) FROM users WHERE email = ? AND id <> ?`, u.Email, u.ID).Scan(&n); err != nil {
			return err
		}
		if n > 0 {
			return ErrConflictT("email already exists")
		}
	}
	now := time.Now().UTC()
	res, err := s.db.ExecContext(ctx,
		`UPDATE users SET username=?, email=?, password_hash=?, role=?, status=?, last_login_at=?, updated_at=? WHERE id=?`,
		u.Username, u.Email, u.PasswordHash, string(u.Role), string(u.Status), ms(u.LastLoginAt), ms(now), u.ID)
	if err != nil {
		return err
	}
	if rows, _ := res.RowsAffected(); rows == 0 {
		return ErrNotFoundT("user")
	}
	u.UpdatedAt = now
	return nil
}

func (s *SQLiteStore) ListUsers(ctx context.Context) ([]*User, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+userCols+` FROM users ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]*User, 0, 8)
	for rows.Next() {
		u, err := scanUser(rows.Scan)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// ---- Projects ----

func (s *SQLiteStore) CreateProject(ctx context.Context, p *Project) error {
	now := time.Now().UTC()
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO projects (name, description, owner_id, created_at, updated_at) VALUES (?,?,?,?,?)`,
		p.Name, p.Description, p.OwnerID, ms(now), ms(now))
	if err != nil {
		return err
	}
	p.ID, _ = res.LastInsertId()
	p.CreatedAt, p.UpdatedAt = now, now
	return nil
}

func (s *SQLiteStore) GetProject(ctx context.Context, id int64) (*Project, error) {
	var (
		p                       Project
		created, updated, owner int64
	)
	err := s.db.QueryRowContext(ctx,
		`SELECT id, name, description, owner_id, created_at, updated_at FROM projects WHERE id = ?`, id).
		Scan(&p.ID, &p.Name, &p.Description, &owner, &created, &updated)
	if errorsIsNoRows(err) {
		return nil, ErrNotFoundT("project")
	}
	if err != nil {
		return nil, err
	}
	p.OwnerID, p.CreatedAt, p.UpdatedAt = owner, msToTime(created), msToTime(updated)
	return &p, nil
}

func (s *SQLiteStore) ListProjects(ctx context.Context) ([]*Project, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, description, owner_id, created_at, updated_at FROM projects ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]*Project, 0, 4)
	for rows.Next() {
		var (
			p                       Project
			created, updated, owner int64
		)
		if err := rows.Scan(&p.ID, &p.Name, &p.Description, &owner, &created, &updated); err != nil {
			return nil, err
		}
		p.OwnerID, p.CreatedAt, p.UpdatedAt = owner, msToTime(created), msToTime(updated)
		out = append(out, &p)
	}
	return out, rows.Err()
}

func (s *SQLiteStore) AddProjectMember(ctx context.Context, m ProjectMember) error {
	if _, err := s.GetProject(ctx, m.ProjectID); err != nil {
		return ErrNotFoundT("project")
	}
	if _, err := s.GetUser(ctx, m.UserID); err != nil {
		return ErrNotFoundT("user")
	}
	m.JoinedAt = time.Now().UTC()
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO project_members (project_id, user_id, role, joined_at) VALUES (?,?,?,?)
		 ON CONFLICT(project_id, user_id) DO UPDATE SET role = excluded.role`,
		m.ProjectID, m.UserID, string(m.Role), ms(m.JoinedAt))
	return err
}

// ---- Domains ----

func (s *SQLiteStore) CreateDomain(ctx context.Context, d *Domain) error {
	if d.Name == "" {
		return ErrValidationT("domain name required")
	}
	var n int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(1) FROM domains WHERE name = ?`, d.Name).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return ErrConflictT("domain name already exists")
	}
	if d.Status == "" {
		d.Status = "active"
	}
	now := time.Now().UTC()
	ns := jsonOrNull(d.NSRecords, "[]")
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO domains (name, response_ip, txt_payload, ns_records, soa_primary_ns, soa_email, status, created_at, updated_at)
		 VALUES (?,?,?,?,?,?,?,?,?)`,
		d.Name, d.ResponseIP, d.TXTPayload, ns, d.SOAPrimaryNS, d.SOAEmail, d.Status, ms(now), ms(now))
	if err != nil {
		return err
	}
	d.ID, _ = res.LastInsertId()
	d.CreatedAt, d.UpdatedAt = now, now
	return nil
}

const domainCols = `id, name, response_ip, txt_payload, ns_records, soa_primary_ns, soa_email, status, created_at, updated_at`

func scanDomain(scan func(dest ...any) error) (*Domain, error) {
	var (
		d                  Domain
		ns                 string
		created, updated   int64
	)
	if err := scan(&d.ID, &d.Name, &d.ResponseIP, &d.TXTPayload, &ns, &d.SOAPrimaryNS, &d.SOAEmail, &d.Status, &created, &updated); err != nil {
		return nil, err
	}
	if ns != "" && ns != "[]" {
		_ = json.Unmarshal([]byte(ns), &d.NSRecords)
	}
	d.CreatedAt, d.UpdatedAt = msToTime(created), msToTime(updated)
	return &d, nil
}

func (s *SQLiteStore) GetDomain(ctx context.Context, id int64) (*Domain, error) {
	d, err := scanDomain(s.db.QueryRowContext(ctx, `SELECT `+domainCols+` FROM domains WHERE id = ?`, id).Scan)
	if errorsIsNoRows(err) {
		return nil, ErrNotFoundT("domain")
	}
	return d, err
}

func (s *SQLiteStore) GetDomainByName(ctx context.Context, name string) (*Domain, error) {
	d, err := scanDomain(s.db.QueryRowContext(ctx, `SELECT `+domainCols+` FROM domains WHERE name = ?`, name).Scan)
	if errorsIsNoRows(err) {
		return nil, ErrNotFoundT("domain")
	}
	return d, err
}

func (s *SQLiteStore) ListDomains(ctx context.Context) ([]*Domain, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+domainCols+` FROM domains ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]*Domain, 0, 4)
	for rows.Next() {
		d, err := scanDomain(rows.Scan)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// ---- Tokens ----

const tokenCols = `id, value, domain_id, user_id, project_id, note, status, created_at, expires_at, revoked_at`

func scanToken(scan func(dest ...any) error) (*Token, error) {
	var (
		t                Token
		status           string
		created, expires int64
		revoked          sql.NullInt64
	)
	if err := scan(&t.ID, &t.Value, &t.DomainID, &t.UserID, &t.ProjectID, &t.Note, &status, &created, &expires, &revoked); err != nil {
		return nil, err
	}
	t.Status = TokenStatus(status)
	t.CreatedAt, t.ExpiresAt = msToTime(created), msToTime(expires)
	if revoked.Valid {
		rt := msToTime(revoked.Int64)
		t.RevokedAt = &rt
	}
	return &t, nil
}

func (s *SQLiteStore) CreateToken(ctx context.Context, t *Token) error {
	if t.Value == "" {
		return ErrValidationT("token value required")
	}
	var n int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(1) FROM tokens WHERE value = ?`, t.Value).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return ErrConflictT("token value already exists")
	}
	now := time.Now().UTC()
	if t.Status == "" {
		t.Status = TokenActive
	}
	var revoked any
	if t.RevokedAt != nil {
		revoked = ms(*t.RevokedAt)
	}
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO tokens (value, domain_id, user_id, project_id, note, status, created_at, expires_at, revoked_at)
		 VALUES (?,?,?,?,?,?,?,?,?)`,
		t.Value, t.DomainID, t.UserID, t.ProjectID, t.Note, string(t.Status), ms(now), ms(t.ExpiresAt), revoked)
	if err != nil {
		return err
	}
	t.ID, _ = res.LastInsertId()
	t.CreatedAt = now
	return nil
}

func (s *SQLiteStore) GetToken(ctx context.Context, id int64) (*Token, error) {
	t, err := scanToken(s.db.QueryRowContext(ctx, `SELECT `+tokenCols+` FROM tokens WHERE id = ?`, id).Scan)
	if errorsIsNoRows(err) {
		return nil, ErrNotFoundT("token")
	}
	return t, err
}

func (s *SQLiteStore) GetTokenByValue(ctx context.Context, value string) (*Token, error) {
	t, err := scanToken(s.db.QueryRowContext(ctx, `SELECT `+tokenCols+` FROM tokens WHERE value = ?`, value).Scan)
	if errorsIsNoRows(err) {
		return nil, ErrNotFoundT("token")
	}
	return t, err
}

func (s *SQLiteStore) listTokens(ctx context.Context, where string, arg any) ([]*Token, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+tokenCols+` FROM tokens WHERE `+where+` ORDER BY created_at DESC, id DESC`, arg)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]*Token, 0, 4)
	for rows.Next() {
		t, err := scanToken(rows.Scan)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (s *SQLiteStore) ListTokensByUser(ctx context.Context, userID int64) ([]*Token, error) {
	return s.listTokens(ctx, `user_id = ?`, userID)
}

func (s *SQLiteStore) ListTokensByProject(ctx context.Context, projectID int64) ([]*Token, error) {
	return s.listTokens(ctx, `project_id = ?`, projectID)
}

func (s *SQLiteStore) UpdateTokenStatus(ctx context.Context, id int64, status TokenStatus) error {
	res, err := s.db.ExecContext(ctx, `UPDATE tokens SET status = ? WHERE id = ?`, string(status), id)
	if err != nil {
		return err
	}
	if rows, _ := res.RowsAffected(); rows == 0 {
		return ErrNotFoundT("token")
	}
	return nil
}

func (s *SQLiteStore) RevokeToken(ctx context.Context, id int64) error {
	now := time.Now().UTC()
	res, err := s.db.ExecContext(ctx,
		`UPDATE tokens SET status = ?, revoked_at = ? WHERE id = ?`, string(TokenRevoked), ms(now), id)
	if err != nil {
		return err
	}
	if rows, _ := res.RowsAffected(); rows == 0 {
		return ErrNotFoundT("token")
	}
	return nil
}

func (s *SQLiteStore) DeleteToken(ctx context.Context, id int64) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM tokens WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if rows, _ := res.RowsAffected(); rows == 0 {
		return ErrNotFoundT("token")
	}
	return nil
}

func (s *SQLiteStore) MarkExpiredTokens(ctx context.Context, now time.Time) (int, error) {
	res, err := s.db.ExecContext(ctx,
		`UPDATE tokens SET status = ? WHERE status = ? AND expires_at < ?`,
		string(TokenExpired), string(TokenActive), ms(now))
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// DeletePurgedTokens removes tokens that expired more than grace ago.
// Interactions survive (they keep the denormalized TokenValue).
func (s *SQLiteStore) DeletePurgedTokens(ctx context.Context, now time.Time, grace time.Duration) (int, error) {
	cutoff := now.Add(-grace)
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM tokens WHERE status = ? AND expires_at < ?`, string(TokenExpired), ms(cutoff))
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	if n > 0 {
		s.maintenance()
	}
	return int(n), nil
}

// ---- Interactions ----

func scanInteraction(scan func(dest ...any) error) (Interaction, error) {
	var (
		iv       Interaction
		typ      string
		headers  string
		labels   string
		created  int64
	)
	err := scan(&iv.ID, &iv.TokenValue, &iv.TokenID, &iv.DomainID, &typ, &iv.SubType, &iv.Protocol,
		&iv.SrcIP, &iv.SrcPort, &iv.Method, &iv.Path, &iv.Query, &headers, &iv.Cookie,
		&iv.UserAgent, &iv.Referer, &iv.Body, &iv.QName, &iv.QType, &labels, &iv.RawRequest, &created)
	if err != nil {
		return iv, err
	}
	iv.Type = InteractionType(typ)
	if headers != "" && headers != "{}" {
		_ = json.Unmarshal([]byte(headers), &iv.Headers)
	}
	if labels != "" && labels != "[]" {
		_ = json.Unmarshal([]byte(labels), &iv.Labels)
	}
	iv.CreatedAt = msToTime(created)
	return iv, nil
}

// AddInteractions inserts a batch in one transaction (the bus already batches
// at 64 rows / 50ms), then enforces capacity caps threshold-style to avoid
// deleting on every batch.
func (s *SQLiteStore) AddInteractions(ctx context.Context, batch []Interaction) (int, error) {
	if len(batch) == 0 {
		return 0, nil
	}
	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	default:
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	touched := make(map[string]bool, len(batch))
	for i := range batch {
		iv := batch[i]
		if iv.CreatedAt.IsZero() {
			iv.CreatedAt = time.Now().UTC()
		}
		if s.bodyTruncate > 0 && len(iv.Body) > s.bodyTruncate { // second guard after edge truncation
			iv.Body = iv.Body[:s.bodyTruncate]
		}
		headers := jsonOrNull(iv.Headers, "{}")
		labels := jsonOrNull(iv.Labels, "[]")
		res, err := tx.ExecContext(ctx, insertInteractionSQL,
			iv.TokenValue, iv.TokenID, iv.DomainID, string(iv.Type), iv.SubType, iv.Protocol,
			iv.SrcIP, iv.SrcPort, iv.Method, iv.Path, iv.Query, headers, iv.Cookie,
			iv.UserAgent, iv.Referer, iv.Body, iv.QName, iv.QType, labels, iv.RawRequest, ms(iv.CreatedAt))
		if err != nil {
			return 0, err
		}
		if id, err := res.LastInsertId(); err == nil {
			iv.ID = id
		}
		if iv.TokenValue != "" {
			touched[iv.TokenValue] = true
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	s.enforceCaps(ctx, touched)
	return len(batch), nil
}

// enforceCaps mirrors the memory backend: global FIFO eviction and per-token
// retention, but only triggered when a cap is actually exceeded.
func (s *SQLiteStore) enforceCaps(ctx context.Context, touched map[string]bool) {
	if s.maxPerToken > 0 {
		for tv := range touched {
			var n int
			if err := s.db.QueryRowContext(ctx,
				`SELECT COUNT(1) FROM interactions WHERE token_value = ?`, tv).Scan(&n); err != nil || n <= s.maxPerToken {
				continue
			}
			if _, err := s.db.ExecContext(ctx,
				`DELETE FROM interactions WHERE token_value = ? AND id NOT IN
				 (SELECT id FROM interactions WHERE token_value = ? ORDER BY id DESC LIMIT ?)`,
				tv, tv, s.maxPerToken); err != nil {
				s.log.Warn("sqlite per-token cap", "err", err)
			}
		}
	}
	if s.maxInteractions > 0 {
		var n int
		if err := s.db.QueryRowContext(ctx, `SELECT COUNT(1) FROM interactions`).Scan(&n); err != nil || n <= s.maxInteractions {
			return
		}
		if _, err := s.db.ExecContext(ctx,
			`DELETE FROM interactions WHERE id NOT IN
			 (SELECT id FROM interactions ORDER BY id DESC LIMIT ?)`, s.maxInteractions); err != nil {
			s.log.Warn("sqlite global cap", "err", err)
		}
	}
}

func (s *SQLiteStore) GetInteraction(ctx context.Context, id int64) (*Interaction, error) {
	iv, err := scanInteraction(s.db.QueryRowContext(ctx,
		`SELECT `+interactionCols+` FROM interactions WHERE id = ?`, id).Scan)
	if errorsIsNoRows(err) {
		return nil, ErrNotFoundT("interaction")
	}
	if err != nil {
		return nil, err
	}
	return &iv, nil
}

func (s *SQLiteStore) ListInteractions(ctx context.Context, f InteractionFilter) ([]Interaction, int, error) {
	limit := f.Limit
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	// Fail-closed ownership scope (same semantics as memory): a non-nil but
	// EMPTY TokenValues set must yield zero results, never a global view.
	if f.TokenValues != nil && len(f.TokenValues) == 0 {
		return []Interaction{}, 0, nil
	}

	where := []string{"1=1"}
	args := []any{}
	if len(f.TokenValues) > 0 {
		where = append(where, `token_value IN (`+strings.TrimSuffix(strings.Repeat("?,", len(f.TokenValues)), ",")+`)`)
		for _, tv := range f.TokenValues {
			args = append(args, tv)
		}
	}
	if f.TokenValue != "" {
		where = append(where, `token_value = ?`)
		args = append(args, f.TokenValue)
	}
	if f.Type != "" {
		where = append(where, `type = ?`)
		args = append(args, string(f.Type))
	}
	if f.SrcIP != "" {
		where = append(where, `src_ip = ?`)
		args = append(args, f.SrcIP)
	}
	if f.DomainID != 0 {
		where = append(where, `domain_id = ?`)
		args = append(args, f.DomainID)
	}
	if f.StartTime != nil {
		where = append(where, `created_at >= ?`)
		args = append(args, ms(*f.StartTime))
	}
	if f.EndTime != nil {
		where = append(where, `created_at <= ?`)
		args = append(args, ms(*f.EndTime))
	}
	w := strings.Join(where, " AND ")

	var total int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(1) FROM interactions WHERE `+w, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	rows, err := s.db.QueryContext(ctx,
		`SELECT `+interactionCols+` FROM interactions WHERE `+w+` ORDER BY id DESC LIMIT ? OFFSET ?`,
		append(args, limit, f.Offset)...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	items := make([]Interaction, 0, min(limit, max(total, 1)))
	for rows.Next() {
		iv, err := scanInteraction(rows.Scan)
		if err != nil {
			return nil, 0, err
		}
		items = append(items, iv)
	}
	return items, total, rows.Err()
}

func (s *SQLiteStore) DeleteInteraction(ctx context.Context, id int64) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM interactions WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if rows, _ := res.RowsAffected(); rows == 0 {
		return ErrNotFoundT("interaction")
	}
	return nil
}

func (s *SQLiteStore) CountInteractionsByToken(ctx context.Context, tokenValue string) (int, error) {
	var n int
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(1) FROM interactions WHERE token_value = ?`, tokenValue).Scan(&n); err != nil {
		return 0, err
	}
	return n, nil
}

// InteractionStatsByTokens returns visitor-scoped counters for the given
// token values: total interactions, per-type counts and the 10 most recent.
func (s *SQLiteStore) InteractionStatsByTokens(ctx context.Context, tokenValues []string) (*Stats, error) {
	st := &Stats{Recent: []Interaction{}}
	if len(tokenValues) == 0 {
		return st, nil
	}
	ph := strings.TrimSuffix(strings.Repeat("?,", len(tokenValues)), ",")
	args := make([]any, 0, len(tokenValues))
	for _, tv := range tokenValues {
		args = append(args, tv)
	}
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(1),
		        COALESCE(SUM(CASE WHEN type = 'dns' THEN 1 ELSE 0 END), 0),
		        COALESCE(SUM(CASE WHEN type = 'http' THEN 1 ELSE 0 END), 0)
		 FROM interactions WHERE token_value IN (`+ph+`)`, args...).
		Scan(&st.Interactions, &st.DNSEvents, &st.HTTPEvents); err != nil {
		return nil, err
	}
	if st.Interactions > 0 {
		rows, err := s.db.QueryContext(ctx,
			`SELECT `+interactionCols+` FROM interactions WHERE token_value IN (`+ph+`) ORDER BY id DESC LIMIT 10`, args...)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		for rows.Next() {
			iv, err := scanInteraction(rows.Scan)
			if err != nil {
				return nil, err
			}
			st.Recent = append(st.Recent, iv)
		}
		if err := rows.Err(); err != nil {
			return nil, err
		}
	}
	return st, nil
}

// DeleteOldInteractions removes interactions older than cutoff, then shrinks
// the WAL and returns freed pages to the OS.
func (s *SQLiteStore) DeleteOldInteractions(ctx context.Context, cutoff time.Time) (int, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM interactions WHERE created_at < ?`, ms(cutoff))
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	if n > 0 {
		s.maintenance()
	}
	return int(n), nil
}

// ---- Logs ----

func (s *SQLiteStore) AddLog(ctx context.Context, l *LogEntry) error {
	if l.CreatedAt.IsZero() {
		l.CreatedAt = time.Now().UTC()
	}
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO logs (user_id, action, target_type, target_id, detail, ip, created_at) VALUES (?,?,?,?,?,?,?)`,
		l.UserID, l.Action, l.TargetType, l.TargetID, l.Detail, l.IP, ms(l.CreatedAt))
	if err != nil {
		return err
	}
	l.ID, _ = res.LastInsertId()
	return nil
}

func (s *SQLiteStore) ListLogs(ctx context.Context, limit int) ([]*LogEntry, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, user_id, action, target_type, target_id, detail, ip, created_at FROM logs ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]*LogEntry, 0, 8)
	for rows.Next() {
		var (
			l       LogEntry
			created int64
		)
		if err := rows.Scan(&l.ID, &l.UserID, &l.Action, &l.TargetType, &l.TargetID, &l.Detail, &l.IP, &created); err != nil {
			return nil, err
		}
		l.CreatedAt = msToTime(created)
		out = append(out, &l)
	}
	return out, rows.Err()
}

// ---- Refresh tokens ----

func (s *SQLiteStore) CreateRefreshToken(ctx context.Context, rt *RefreshToken) error {
	if rt.TokenHash == "" {
		return ErrValidationT("token hash required")
	}
	var n int
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(1) FROM refresh_tokens WHERE token_hash = ?`, rt.TokenHash).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return ErrConflictT("refresh token already exists")
	}
	if rt.CreatedAt.IsZero() {
		rt.CreatedAt = time.Now().UTC()
	}
	var revoked any
	if rt.RevokedAt != nil {
		revoked = ms(*rt.RevokedAt)
	}
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO refresh_tokens (user_id, token_hash, expires_at, revoked_at, created_at, ip) VALUES (?,?,?,?,?,?)`,
		rt.UserID, rt.TokenHash, ms(rt.ExpiresAt), revoked, ms(rt.CreatedAt), rt.IP)
	if err != nil {
		return err
	}
	rt.ID, _ = res.LastInsertId()
	return nil
}

func (s *SQLiteStore) GetRefreshTokenByHash(ctx context.Context, hash string) (*RefreshToken, error) {
	var (
		rt               RefreshToken
		created, expires int64
		revoked          sql.NullInt64
	)
	err := s.db.QueryRowContext(ctx,
		`SELECT id, user_id, token_hash, expires_at, revoked_at, created_at, ip FROM refresh_tokens WHERE token_hash = ?`, hash).
		Scan(&rt.ID, &rt.UserID, &rt.TokenHash, &expires, &revoked, &created, &rt.IP)
	if errorsIsNoRows(err) {
		return nil, ErrNotFoundT("refresh token")
	}
	if err != nil {
		return nil, err
	}
	rt.ExpiresAt, rt.CreatedAt = msToTime(expires), msToTime(created)
	if revoked.Valid {
		r := msToTime(revoked.Int64)
		rt.RevokedAt = &r
	}
	return &rt, nil
}

func (s *SQLiteStore) RevokeRefreshToken(ctx context.Context, id int64) error {
	now := time.Now().UTC()
	res, err := s.db.ExecContext(ctx,
		`UPDATE refresh_tokens SET revoked_at = ? WHERE id = ?`, ms(now), id)
	if err != nil {
		return err
	}
	if rows, _ := res.RowsAffected(); rows == 0 {
		return ErrNotFoundT("refresh token")
	}
	return nil
}

func (s *SQLiteStore) DeleteExpiredRefreshTokens(ctx context.Context, now time.Time) (int, error) {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM refresh_tokens WHERE expires_at < ? OR (revoked_at IS NOT NULL AND revoked_at < ?)`,
		ms(now), ms(now.Add(-24*time.Hour)))
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// ---- Stats ----

func (s *SQLiteStore) Stats(ctx context.Context) (*Stats, error) {
	st := &Stats{Recent: []Interaction{}}
	count := func(query string, dest *int64) error {
		return s.db.QueryRowContext(ctx, query).Scan(dest)
	}
	for _, q := range []struct {
		sql string
		dst *int64
	}{
		{`SELECT COUNT(1) FROM users`, &st.Users},
		{`SELECT COUNT(1) FROM projects`, &st.Projects},
		{`SELECT COUNT(1) FROM domains`, &st.Domains},
		{`SELECT COUNT(1) FROM tokens`, &st.Tokens},
		{`SELECT COUNT(1) FROM tokens WHERE status = 'active'`, &st.ActiveTokens},
		{`SELECT COUNT(1) FROM interactions`, &st.Interactions},
		{`SELECT COUNT(1) FROM interactions WHERE type = 'dns'`, &st.DNSEvents},
		{`SELECT COUNT(1) FROM interactions WHERE type = 'http'`, &st.HTTPEvents},
	} {
		if err := count(q.sql, q.dst); err != nil {
			return nil, err
		}
	}
	if st.Interactions > 0 {
		rows, err := s.db.QueryContext(ctx,
			`SELECT `+interactionCols+` FROM interactions ORDER BY id DESC LIMIT 10`)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		for rows.Next() {
			iv, err := scanInteraction(rows.Scan)
			if err != nil {
				return nil, err
			}
			st.Recent = append(st.Recent, iv)
		}
		if err := rows.Err(); err != nil {
			return nil, err
		}
	}
	return st, nil
}

// errorsIsNoRows reports whether err is database/sql's ErrNoRows.
func errorsIsNoRows(err error) bool { return err == sql.ErrNoRows }

// compile-time check: SQLiteStore must satisfy the full Store contract.
var _ Store = (*SQLiteStore)(nil)
