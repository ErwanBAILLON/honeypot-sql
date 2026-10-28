package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Postgres stores sessions and events in two tables created on startup.
type Postgres struct {
	pool *pgxpool.Pool
}

const schema = `
CREATE TABLE IF NOT EXISTS sessions (
  id            BIGSERIAL PRIMARY KEY,
  proto         TEXT NOT NULL,
  remote_ip     INET NOT NULL,
  remote_port   INT NOT NULL,
  started_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  ended_at      TIMESTAMPTZ,
  username      TEXT NOT NULL DEFAULT '',
  database      TEXT NOT NULL DEFAULT '',
  password_seen TEXT NOT NULL DEFAULT '',
  client_info   JSONB NOT NULL DEFAULT '{}'::jsonb,
  bytes_in      BIGINT NOT NULL DEFAULT 0,
  bytes_out     BIGINT NOT NULL DEFAULT 0,
  country       TEXT NOT NULL DEFAULT '',
  asn           INT NOT NULL DEFAULT 0,
  as_org        TEXT NOT NULL DEFAULT ''
);
-- Added after the first release; harmless on a fresh database, additive on an existing one.
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS country TEXT NOT NULL DEFAULT '';
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS asn INT NOT NULL DEFAULT 0;
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS as_org TEXT NOT NULL DEFAULT '';
CREATE INDEX IF NOT EXISTS sessions_started_at_idx ON sessions (started_at DESC);
CREATE INDEX IF NOT EXISTS sessions_remote_ip_idx ON sessions (remote_ip);
CREATE INDEX IF NOT EXISTS sessions_country_idx ON sessions (country);
CREATE TABLE IF NOT EXISTS events (
  id         BIGSERIAL PRIMARY KEY,
  session_id BIGINT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
  ts         TIMESTAMPTZ NOT NULL DEFAULT now(),
  kind       TEXT NOT NULL,
  payload    JSONB NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX IF NOT EXISTS events_session_id_idx ON events (session_id);
CREATE TABLE IF NOT EXISTS canary_tokens (
  id         BIGSERIAL PRIMARY KEY,
  token      TEXT NOT NULL UNIQUE,
  kind       TEXT NOT NULL,
  session_id BIGINT REFERENCES sessions(id) ON DELETE SET NULL,
  label      TEXT NOT NULL DEFAULT '',
  issued_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS canary_hits (
  id          BIGSERIAL PRIMARY KEY,
  token       TEXT NOT NULL,
  channel     TEXT NOT NULL,
  source_ip   TEXT NOT NULL DEFAULT '',
  source_port INT NOT NULL DEFAULT 0,
  country     TEXT NOT NULL DEFAULT '',
  asn         INT NOT NULL DEFAULT 0,
  as_org      TEXT NOT NULL DEFAULT '',
  ts          TIMESTAMPTZ NOT NULL DEFAULT now(),
  detail      JSONB NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX IF NOT EXISTS canary_hits_token_idx ON canary_hits (token);
`

// NewPostgres connects and applies the schema (idempotent).
func NewPostgres(ctx context.Context, url string) (*Postgres, error) {
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		return nil, fmt.Errorf("parse DATABASE_URL: %w", err)
	}
	cfg.MaxConns = 5
	cfg.MinConns = 1
	cfg.MaxConnLifetime = 30 * time.Minute
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}
	ctx2, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	if _, err := pool.Exec(ctx2, schema); err != nil {
		pool.Close()
		return nil, fmt.Errorf("apply schema: %w", err)
	}
	return &Postgres{pool: pool}, nil
}

func (p *Postgres) StartSession(ctx context.Context, s *Session) error {
	ci, _ := json.Marshal(nilToEmpty(s.ClientInfo))
	return p.pool.QueryRow(ctx, `INSERT INTO sessions (proto, remote_ip, remote_port, started_at, username, database, password_seen, client_info, country, asn, as_org)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING id`,
		s.Proto, s.RemoteIP, s.RemotePort, s.StartedAt, s.Username, s.Database, s.PasswordSeen, ci, s.Country, s.ASN, s.ASOrg).Scan(&s.ID)
}

func (p *Postgres) UpdateSession(ctx context.Context, s *Session) error {
	ci, _ := json.Marshal(nilToEmpty(s.ClientInfo))
	_, err := p.pool.Exec(ctx, `UPDATE sessions SET ended_at=$2, username=$3, database=$4, password_seen=$5, client_info=$6, bytes_in=$7, bytes_out=$8 WHERE id=$1`,
		s.ID, s.EndedAt, s.Username, s.Database, s.PasswordSeen, ci, s.BytesIn, s.BytesOut)
	return err
}

func (p *Postgres) AddEvent(ctx context.Context, e *Event) error {
	if e.TS.IsZero() {
		e.TS = time.Now()
	}
	pl, _ := json.Marshal(nilToEmpty(e.Payload))
	return p.pool.QueryRow(ctx, `INSERT INTO events (session_id, ts, kind, payload) VALUES ($1,$2,$3,$4) RETURNING id`,
		e.SessionID, e.TS, e.Kind, pl).Scan(&e.ID)
}

const sessionCols = `id, proto, host(remote_ip), remote_port, started_at, ended_at, username, database, password_seen, client_info, bytes_in, bytes_out, country, asn, as_org`

func scanSession(row pgx.Row) (*Session, error) {
	var s Session
	var ci []byte
	if err := row.Scan(&s.ID, &s.Proto, &s.RemoteIP, &s.RemotePort, &s.StartedAt, &s.EndedAt, &s.Username, &s.Database, &s.PasswordSeen, &ci, &s.BytesIn, &s.BytesOut, &s.Country, &s.ASN, &s.ASOrg); err != nil {
		return nil, err
	}
	_ = json.Unmarshal(ci, &s.ClientInfo)
	return &s, nil
}

func (p *Postgres) ListSessions(ctx context.Context, limit int) ([]Session, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := p.pool.Query(ctx, `SELECT `+sessionCols+` FROM sessions ORDER BY id DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Session
	for rows.Next() {
		s, err := scanSession(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *s)
	}
	return out, rows.Err()
}

func (p *Postgres) GetSession(ctx context.Context, id int64) (*Session, []Event, error) {
	s, err := scanSession(p.pool.QueryRow(ctx, `SELECT `+sessionCols+` FROM sessions WHERE id=$1`, id))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil, ErrNotFound
		}
		return nil, nil, err
	}
	rows, err := p.pool.Query(ctx, `SELECT id, session_id, ts, kind, payload FROM events WHERE session_id=$1 ORDER BY id`, id)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	var evs []Event
	for rows.Next() {
		var e Event
		var pl []byte
		if err := rows.Scan(&e.ID, &e.SessionID, &e.TS, &e.Kind, &pl); err != nil {
			return nil, nil, err
		}
		_ = json.Unmarshal(pl, &e.Payload)
		evs = append(evs, e)
	}
	return s, evs, rows.Err()
}

func (p *Postgres) Stats(ctx context.Context) (*Stats, error) {
	st := &Stats{ByProto: map[string]int64{}}
	if err := p.pool.QueryRow(ctx, `SELECT count(*), count(*) FILTER (WHERE started_at > now() - interval '24 hours'),
		count(*) FILTER (WHERE username <> '' OR password_seen <> '') FROM sessions`).Scan(&st.Total, &st.Last24h, &st.WithAuth); err != nil {
		return nil, err
	}
	rows, err := p.pool.Query(ctx, `SELECT proto, count(*) FROM sessions GROUP BY proto`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var k string
		var n int64
		if err := rows.Scan(&k, &n); err != nil {
			rows.Close()
			return nil, err
		}
		st.ByProto[k] = n
	}
	rows.Close()
	var qerr error
	st.TopIPs, qerr = p.counts(ctx, `SELECT host(remote_ip), count(*) FROM sessions GROUP BY 1 ORDER BY 2 DESC, 1 LIMIT 10`)
	if qerr != nil {
		return nil, qerr
	}
	st.TopCountries, qerr = p.counts(ctx, `SELECT country, count(*) FROM sessions WHERE country <> '' GROUP BY 1 ORDER BY 2 DESC, 1 LIMIT 10`)
	if qerr != nil {
		return nil, qerr
	}
	st.TopASNs, qerr = p.counts(ctx, `SELECT 'AS' || asn || ' ' || max(as_org), count(*) FROM sessions WHERE asn <> 0 GROUP BY asn ORDER BY 2 DESC, 1 LIMIT 10`)
	if qerr != nil {
		return nil, qerr
	}
	st.TopUsernames, qerr = p.counts(ctx, `SELECT username, count(*) FROM sessions WHERE username <> '' OR password_seen <> '' GROUP BY 1 ORDER BY 2 DESC, 1 LIMIT 10`)
	if qerr != nil {
		return nil, qerr
	}
	st.TopPasswords, qerr = p.counts(ctx, `SELECT password_seen, count(*) FROM sessions WHERE username <> '' OR password_seen <> '' GROUP BY 1 ORDER BY 2 DESC, 1 LIMIT 10`)
	if qerr != nil {
		return nil, qerr
	}
	st.TopQueries, qerr = p.counts(ctx, `SELECT payload->>'sql', count(*) FROM events WHERE kind='query' AND payload ? 'sql' GROUP BY 1 ORDER BY 2 DESC, 1 LIMIT 15`)
	if qerr != nil {
		return nil, qerr
	}
	return st, nil
}

func (p *Postgres) counts(ctx context.Context, q string) ([]Count, error) {
	rows, err := p.pool.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Count
	for rows.Next() {
		var c Count
		if err := rows.Scan(&c.Value, &c.N); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (p *Postgres) IssueToken(ctx context.Context, t *CanaryToken) error {
	if t.IssuedAt.IsZero() {
		t.IssuedAt = time.Now()
	}
	var sid any
	if t.SessionID != 0 {
		sid = t.SessionID
	}
	return p.pool.QueryRow(ctx, `INSERT INTO canary_tokens (token, kind, session_id, label, issued_at)
		VALUES ($1,$2,$3,$4,$5) RETURNING id`, t.Token, t.Kind, sid, t.Label, t.IssuedAt).Scan(&t.ID)
}

func (p *Postgres) FindToken(ctx context.Context, token string) (*CanaryToken, error) {
	var t CanaryToken
	var sid *int64
	err := p.pool.QueryRow(ctx, `SELECT id, token, kind, COALESCE(session_id,0), label, issued_at FROM canary_tokens WHERE token=$1`, token).
		Scan(&t.ID, &t.Token, &t.Kind, &sid, &t.Label, &t.IssuedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	if sid != nil {
		t.SessionID = *sid
	}
	return &t, nil
}

func (p *Postgres) RecordHit(ctx context.Context, h *CanaryHit) error {
	if h.TS.IsZero() {
		h.TS = time.Now()
	}
	detail, _ := json.Marshal(nilToEmpty(h.Detail))
	return p.pool.QueryRow(ctx, `INSERT INTO canary_hits (token, channel, source_ip, source_port, country, asn, as_org, ts, detail)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING id`,
		h.Token, h.Channel, h.SourceIP, h.SourcePort, h.Country, h.ASN, h.ASOrg, h.TS, detail).Scan(&h.ID)
}

func (p *Postgres) Canaries(ctx context.Context, limit int) ([]Canary, error) {
	if limit <= 0 {
		limit = 200
	}
	rows, err := p.pool.Query(ctx, `
		SELECT t.id, t.token, t.kind, COALESCE(t.session_id,0), t.label, t.issued_at,
		       COALESCE(host(s.remote_ip),''), COALESCE(s.country,''),
		       (SELECT count(*) FROM canary_hits h WHERE h.token=t.token),
		       COALESCE(lh.source_ip,''), COALESCE(lh.country,''), COALESCE(lh.channel,''), lh.ts
		FROM canary_tokens t
		LEFT JOIN sessions s ON s.id = t.session_id
		LEFT JOIN LATERAL (
		  SELECT source_ip, country, channel, ts FROM canary_hits h
		  WHERE h.token = t.token ORDER BY ts DESC LIMIT 1
		) lh ON true
		ORDER BY (lh.ts IS NOT NULL) DESC, lh.ts DESC NULLS LAST, t.issued_at DESC
		LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Canary
	for rows.Next() {
		var c Canary
		if err := rows.Scan(&c.ID, &c.Token, &c.Kind, &c.SessionID, &c.Label, &c.IssuedAt,
			&c.IssuerIP, &c.IssuerCountry, &c.Hits, &c.LastHitIP, &c.LastHitCountry, &c.LastHitChannel, &c.LastHitAt); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (p *Postgres) Ping(ctx context.Context) error { return p.pool.Ping(ctx) }
func (p *Postgres) Close()                         { p.pool.Close() }

func nilToEmpty(m map[string]any) map[string]any {
	if m == nil {
		return map[string]any{}
	}
	return m
}
