// Package store persists honeypot sessions and events.
//
// Two implementations: Postgres (pgx) for production and an in-memory ring
// buffer used when DATABASE_URL is empty (tests, local runs).
package store

import (
	"context"
	"time"
)

// Session is one TCP connection to a honeypot listener.
type Session struct {
	ID           int64          `json:"id"`
	Proto        string         `json:"proto"` // "mysql" | "postgres"
	RemoteIP     string         `json:"remote_ip"`
	RemotePort   int            `json:"remote_port"`
	StartedAt    time.Time      `json:"started_at"`
	EndedAt      *time.Time     `json:"ended_at,omitempty"`
	Username     string         `json:"username"`
	Database     string         `json:"database"`
	PasswordSeen string         `json:"password_seen"`
	ClientInfo   map[string]any `json:"client_info"`
	BytesIn      int64          `json:"bytes_in"`
	BytesOut     int64          `json:"bytes_out"`
}

// Event is something the client did during a session.
type Event struct {
	ID        int64          `json:"id"`
	SessionID int64          `json:"session_id"`
	TS        time.Time      `json:"ts"`
	Kind      string         `json:"kind"` // connect, handshake, auth, query, error, disconnect
	Payload   map[string]any `json:"payload"`
}

// Count is a (value, n) pair used by the dashboard.
type Count struct {
	Value string `json:"value"`
	N     int64  `json:"n"`
}

// Stats is the aggregated view shown on the dashboard.
type Stats struct {
	Total        int64            `json:"total"`
	Last24h      int64            `json:"last_24h"`
	ByProto      map[string]int64 `json:"by_proto"`
	WithAuth     int64            `json:"with_auth"`
	TopIPs       []Count          `json:"top_ips"`
	TopUsernames []Count          `json:"top_usernames"`
	TopPasswords []Count          `json:"top_passwords"`
	TopQueries   []Count          `json:"top_queries"`
}

// Store is implemented by Memory and Postgres.
type Store interface {
	// StartSession inserts the session and fills s.ID.
	StartSession(ctx context.Context, s *Session) error
	// UpdateSession rewrites the mutable columns (credentials, client info, bytes, ended_at).
	UpdateSession(ctx context.Context, s *Session) error
	AddEvent(ctx context.Context, e *Event) error
	ListSessions(ctx context.Context, limit int) ([]Session, error)
	GetSession(ctx context.Context, id int64) (*Session, []Event, error)
	Stats(ctx context.Context) (*Stats, error)
	Ping(ctx context.Context) error
	Close()
}
