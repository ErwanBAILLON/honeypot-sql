// Package hpcore holds what both protocol servers share: the connection
// recorder (bytes, events, JSON log lines) and the accept loop with its
// concurrency cap and timeouts.
package hpcore

import (
	"context"
	"errors"
	"io"
	"log"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"git.ebaillon.fr/infra/honeypot-sql/internal/hplog"
	"git.ebaillon.fr/infra/honeypot-sql/internal/store"
)

// Limits bound what one client can do. Zero values are replaced by defaults.
type Limits struct {
	MaxConns     int           // concurrent connections across the listener (default 500)
	ReadTimeout  time.Duration // per read (default 30s): slowloris protection
	SessionMax   time.Duration // whole session (default 10m)
	MaxQueries   int           // queries answered before closing (default 200)
	MaxPacket    int           // largest client packet accepted (default 1 MiB)
	PasswordTrim int           // password_seen stored length (default 128)
}

func (l *Limits) defaults() {
	if l.MaxConns <= 0 {
		l.MaxConns = 500
	}
	if l.ReadTimeout <= 0 {
		l.ReadTimeout = 30 * time.Second
	}
	if l.SessionMax <= 0 {
		l.SessionMax = 10 * time.Minute
	}
	if l.MaxQueries <= 0 {
		l.MaxQueries = 200
	}
	if l.MaxPacket <= 0 {
		l.MaxPacket = 1 << 20
	}
	if l.PasswordTrim <= 0 {
		l.PasswordTrim = 128
	}
}

// Handler is implemented by a protocol server; it must return when the
// client leaves or when ctx is done.
type Handler interface {
	Proto() string
	Handle(ctx context.Context, s *Session)
}

// Session wraps a net.Conn with recording. Reads/writes count bytes and
// refresh the read deadline. Not safe for concurrent use.
type Session struct {
	Conn    net.Conn
	Rec     store.Session
	Store   store.Store
	Limits  Limits
	Queries int

	bytesIn, bytesOut atomic.Int64
	ctx               context.Context
}

// Read refreshes the deadline and counts bytes.
func (s *Session) Read(p []byte) (int, error) {
	_ = s.Conn.SetReadDeadline(time.Now().Add(s.Limits.ReadTimeout))
	n, err := s.Conn.Read(p)
	s.bytesIn.Add(int64(n))
	return n, err
}

// Write counts bytes; a short write deadline avoids clients that never read.
func (s *Session) Write(p []byte) (int, error) {
	_ = s.Conn.SetWriteDeadline(time.Now().Add(s.Limits.ReadTimeout))
	n, err := s.Conn.Write(p)
	s.bytesOut.Add(int64(n))
	return n, err
}

// ReadFull is io.ReadFull on the counted reader.
func (s *Session) ReadFull(p []byte) error {
	_, err := io.ReadFull(s, p)
	return err
}

// Event records a session event (DB + nothing else).
func (s *Session) Event(kind string, payload map[string]any) {
	e := &store.Event{SessionID: s.Rec.ID, TS: time.Now(), Kind: kind, Payload: BoundPayload(payload, EventMaxJSON)}
	// Own budget: the session ctx may already be expired (timeout) when the
	// disconnect event is written.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.Store.AddEvent(ctx, e); err != nil {
		log.Printf("store: add event: %v", err)
	}
}

// Query records a query and reports whether the client may continue.
func (s *Session) Query(sql string) bool {
	s.Queries++
	hplog.Queries.Inc(s.Rec.Proto)
	s.Event("query", map[string]any{"sql": trim(sql, 4096), "n": s.Queries, "t_ms": time.Since(s.Rec.StartedAt).Milliseconds()})
	return s.Queries < s.Limits.MaxQueries
}

// Credentials stores what the client presented and emits the JSON line
// CrowdSec bans on. password is stored truncated, never hashed: it is the
// attacker's secret, not ours, and the dashboard shows it.
func (s *Session) Credentials(user, database, password string, extra map[string]any) {
	s.Rec.Username = trim(user, 256)
	s.Rec.Database = trim(database, 256)
	s.Rec.PasswordSeen = trim(password, s.Limits.PasswordTrim)
	if s.Rec.ClientInfo == nil {
		s.Rec.ClientInfo = map[string]any{}
	}
	for k, v := range extra {
		s.Rec.ClientInfo[k] = v
	}
	s.Rec.ClientInfo = BoundPayload(s.Rec.ClientInfo, ClientInfoMax)
	hplog.Auth.Inc(s.Rec.Proto)
	if err := s.Store.UpdateSession(s.ctx, &s.Rec); err != nil {
		log.Printf("store: update session: %v", err)
	}
	payload := map[string]any{"username": s.Rec.Username, "database": s.Rec.Database, "password": s.Rec.PasswordSeen}
	for k, v := range extra {
		payload[k] = v
	}
	s.Event("auth", payload)
	hplog.Emit("sql_honeypot_auth", map[string]any{
		"proto": s.Rec.Proto, "remote_ip": s.Rec.RemoteIP, "remote_port": s.Rec.RemotePort,
		"session_id": s.Rec.ID, "username": s.Rec.Username, "database": s.Rec.Database,
		"password_seen": s.Rec.PasswordSeen,
	})
}

// ClientInfo merges non-credential facts (capabilities, versions, parameters).
func (s *Session) ClientInfo(kv map[string]any) {
	if s.Rec.ClientInfo == nil {
		s.Rec.ClientInfo = map[string]any{}
	}
	for k, v := range kv {
		s.Rec.ClientInfo[k] = v
	}
	s.Rec.ClientInfo = BoundPayload(s.Rec.ClientInfo, ClientInfoMax)
}

func trim(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// Serve accepts on ln until ctx is done and runs h for each client.
func Serve(ctx context.Context, ln net.Listener, h Handler, st store.Store, lim Limits) error {
	lim.defaults()
	sem := make(chan struct{}, lim.MaxConns)
	var wg sync.WaitGroup
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				wg.Wait()
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			log.Printf("%s: accept: %v", h.Proto(), err)
			time.Sleep(50 * time.Millisecond)
			continue
		}
		select {
		case sem <- struct{}{}:
		default:
			hplog.Rejected.Inc(h.Proto())
			_ = c.Close()
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			handleConn(ctx, c, h, st, lim)
		}()
	}
}

func handleConn(parent context.Context, c net.Conn, h Handler, st store.Store, lim Limits) {
	defer c.Close()
	hplog.Active.Add(1)
	defer hplog.Active.Add(-1)
	ctx, cancel := context.WithTimeout(parent, lim.SessionMax)
	defer cancel()

	ip, portStr, _ := net.SplitHostPort(c.RemoteAddr().String())
	port, _ := strconv.Atoi(portStr)
	s := &Session{Conn: c, Store: st, Limits: lim, ctx: ctx}
	s.Rec = store.Session{Proto: h.Proto(), RemoteIP: ip, RemotePort: port, StartedAt: time.Now(), ClientInfo: map[string]any{}}
	if err := st.StartSession(ctx, &s.Rec); err != nil {
		log.Printf("store: start session: %v", err)
	}
	hplog.Sessions.Inc(h.Proto())
	s.Event("connect", map[string]any{"local_addr": c.LocalAddr().String()})
	hplog.Emit("sql_honeypot_touch", map[string]any{
		"proto": h.Proto(), "remote_ip": ip, "remote_port": port, "session_id": s.Rec.ID,
	})
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
	}
	// Hard stop at SessionMax even if the handler is blocked in a read.
	stop := context.AfterFunc(ctx, func() { _ = c.SetDeadline(time.Now()) })
	h.Handle(ctx, s)
	stop()

	now := time.Now()
	s.Rec.EndedAt = &now
	s.Rec.BytesIn = s.bytesIn.Load()
	s.Rec.BytesOut = s.bytesOut.Load()
	s.Event("disconnect", map[string]any{"bytes_in": s.Rec.BytesIn, "bytes_out": s.Rec.BytesOut, "queries": s.Queries, "duration_ms": now.Sub(s.Rec.StartedAt).Milliseconds()})
	// The parent ctx may be cancelled during shutdown: give the final write its own budget.
	fctx, fcancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer fcancel()
	if err := st.UpdateSession(fctx, &s.Rec); err != nil {
		log.Printf("store: end session: %v", err)
	}
}
