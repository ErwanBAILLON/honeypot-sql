// Package tests connects to the honeypot with the real MySQL and PostgreSQL
// client libraries and checks what gets recorded.
package tests

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	mysqldrv "github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"git.ebaillon.fr/infra/honeypot-sql/internal/hpcore"
	"git.ebaillon.fr/infra/honeypot-sql/internal/hplog"
	"git.ebaillon.fr/infra/honeypot-sql/internal/mysqlhp"
	"git.ebaillon.fr/infra/honeypot-sql/internal/pghp"
	"git.ebaillon.fr/infra/honeypot-sql/internal/store"
	"git.ebaillon.fr/infra/honeypot-sql/internal/web"
)

type env struct {
	st        *store.Memory
	mysqlAddr string
	pgAddr    string
	logs      *bytes.Buffer
}

func start(t *testing.T, mysqlSrv *mysqlhp.Server, pgSrv *pghp.Server) *env {
	t.Helper()
	st := store.NewMemory(0)
	logs := &bytes.Buffer{}
	hplog.SetOutput(logs)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	lim := hpcore.Limits{ReadTimeout: 5 * time.Second, SessionMax: 20 * time.Second}
	ln1, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln2, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = hpcore.Serve(ctx, ln1, mysqlSrv, st, lim) }()
	go func() { _ = hpcore.Serve(ctx, ln2, pgSrv, st, lim) }()
	return &env{st: st, mysqlAddr: ln1.Addr().String(), pgAddr: ln2.Addr().String(), logs: logs}
}

// waitSession polls until a session matching proto has ended.
// With sslmode=prefer pgx first opens a connection for SSLRequest, gets 'N',
// closes it and reconnects in clear: that first session has no credentials.
func (e *env) waitSession(t *testing.T, proto string) store.Session {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		ss, _ := e.st.ListSessions(context.Background(), 10)
		for _, s := range ss {
			if s.Proto == proto && s.EndedAt != nil && s.Username != "" {
				return s
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("no ended %s session", proto)
	return store.Session{}
}

func TestMySQLClient(t *testing.T) {
	e := start(t, &mysqlhp.Server{Version: "8.0.36"}, &pghp.Server{})
	cfg := mysqldrv.NewConfig()
	cfg.User, cfg.Passwd, cfg.Net, cfg.Addr, cfg.DBName = "root", "hunter2", "tcp", e.mysqlAddr, "shop"
	cfg.Timeout, cfg.ReadTimeout = 5*time.Second, 5*time.Second
	cfg.AllowNativePasswords = true
	db, err := sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Ping(); err != nil {
		t.Fatalf("ping (handshake + auth): %v", err)
	}
	var v string
	if err := db.QueryRow("SELECT VERSION()").Scan(&v); err != nil || v != "8.0.36" {
		t.Fatalf("version = %q err=%v", v, err)
	}
	rows, err := db.Query("SHOW DATABASES")
	if err != nil {
		t.Fatal(err)
	}
	var dbs []string
	for rows.Next() {
		var d string
		_ = rows.Scan(&d)
		dbs = append(dbs, d)
	}
	rows.Close()
	if len(dbs) != 4 || dbs[1] != "mysql" {
		t.Fatalf("databases = %v", dbs)
	}
	_, err = db.Query("SELECT * FROM users")
	var merr *mysqldrv.MySQLError
	if err == nil || !asMySQLErr(err, &merr) || merr.Number != 1146 {
		t.Fatalf("expected ER_NO_SUCH_TABLE, got %v", err)
	}
	db.Close()

	s := e.waitSession(t, "mysql")
	if s.Username != "root" || s.Database != "shop" {
		t.Fatalf("session = %+v", s)
	}
	// hunter2 is not in the honeytoken list nor the common list: only the hash is known.
	if !strings.HasPrefix(s.PasswordSeen, "<sha1:") {
		t.Fatalf("password_seen = %q", s.PasswordSeen)
	}
	caps, _ := s.ClientInfo["capabilities"].([]string)
	if !contains(caps, "PROTOCOL_41") {
		t.Fatalf("capabilities = %v", s.ClientInfo["capabilities"])
	}
	_, evs, _ := e.st.GetSession(context.Background(), s.ID)
	var queries []string
	for _, ev := range evs {
		if ev.Kind == "query" {
			queries = append(queries, ev.Payload["sql"].(string))
		}
	}
	if len(queries) < 3 || queries[0] != "SELECT VERSION()" {
		t.Fatalf("queries = %v", queries)
	}
	if !strings.Contains(e.logs.String(), `"event":"sql_honeypot_auth"`) || !strings.Contains(e.logs.String(), `"username":"root"`) {
		t.Fatalf("json log missing auth line: %s", e.logs.String())
	}
}

func TestMySQLHoneytokenRejects(t *testing.T) {
	e := start(t, &mysqlhp.Server{Passwords: []string{"letmein"}}, &pghp.Server{})
	dsn := fmt.Sprintf("root:wrong@tcp(%s)/?timeout=5s&readTimeout=5s", e.mysqlAddr)
	db, _ := sql.Open("mysql", dsn)
	defer db.Close()
	err := db.Ping()
	var merr *mysqldrv.MySQLError
	if err == nil || !asMySQLErr(err, &merr) || merr.Number != 1045 {
		t.Fatalf("expected access denied, got %v", err)
	}
	db.Close()
	dsn = fmt.Sprintf("root:letmein@tcp(%s)/?timeout=5s&readTimeout=5s", e.mysqlAddr)
	db2, _ := sql.Open("mysql", dsn)
	defer db2.Close()
	if err := db2.Ping(); err != nil {
		t.Fatalf("honeytoken must be accepted: %v", err)
	}
	db2.Close()
	ss, _ := e.st.ListSessions(context.Background(), 10)
	if len(ss) != 2 || ss[0].PasswordSeen != "letmein" {
		t.Fatalf("sessions = %+v", ss)
	}
}

func TestPostgresClient(t *testing.T) {
	e := start(t, &mysqlhp.Server{}, &pghp.Server{Version: "16.3"})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// sslmode=prefer (default) exercises the SSLRequest -> 'N' fallback.
	conn, err := pgx.Connect(ctx, fmt.Sprintf("postgres://admin:Passw0rd@%s/prod?application_name=hp-test", e.pgAddr))
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	var v string
	if err := conn.QueryRow(ctx, "select version()").Scan(&v); err != nil || !strings.HasPrefix(v, "PostgreSQL 16.3") {
		t.Fatalf("version = %q err=%v", v, err)
	}
	var one string
	if err := conn.QueryRow(ctx, "select 1").Scan(&one); err != nil || one != "1" {
		t.Fatalf("select 1 = %q err=%v", one, err)
	}
	rows, err := conn.Query(ctx, "SELECT d.datname as \"Name\" FROM pg_catalog.pg_database d ORDER BY 1")
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for rows.Next() {
		n++
	}
	rows.Close()
	if n != 3 {
		t.Fatalf("pg_database rows = %d", n)
	}
	_, err = conn.Exec(ctx, "select * from secrets")
	var perr *pgconn.PgError
	if err == nil || !asPgErr(err, &perr) || perr.Code != "42P01" {
		t.Fatalf("expected 42P01, got %v", err)
	}
	// Simple protocol too (psql, most scanners).
	if _, err := conn.Exec(ctx, "set client_encoding to 'UTF8'"); err != nil {
		t.Fatalf("set: %v", err)
	}
	conn.Close(ctx)

	s := e.waitSession(t, "postgres")
	if s.Username != "admin" || s.Database != "prod" || s.PasswordSeen != "Passw0rd" {
		t.Fatalf("session = %+v", s)
	}
	if s.ClientInfo["application_name"] != "hp-test" {
		t.Fatalf("client_info = %v", s.ClientInfo)
	}
	// The SSLRequest probe is a session of its own (pgx reconnects after 'N').
	ss, _ := e.st.ListSessions(context.Background(), 10)
	sawSSL := false
	for _, x := range ss {
		if x.ClientInfo["ssl_request"] == true {
			sawSSL = true
		}
	}
	if !sawSSL {
		t.Fatalf("no SSLRequest session recorded: %+v", ss)
	}
	if !strings.Contains(e.logs.String(), `"password_seen":"Passw0rd"`) {
		t.Fatalf("json log missing password: %s", e.logs.String())
	}
}

func TestPostgresMD5(t *testing.T) {
	e := start(t, &mysqlhp.Server{}, &pghp.Server{AuthMD5: true, Passwords: []string{"tok3n"}})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := pgx.Connect(ctx, fmt.Sprintf("postgres://u:bad@%s/x?sslmode=disable", e.pgAddr)); err == nil {
		t.Fatalf("wrong password must be rejected")
	}
	conn, err := pgx.Connect(ctx, fmt.Sprintf("postgres://u:tok3n@%s/x?sslmode=disable", e.pgAddr))
	if err != nil {
		t.Fatalf("honeytoken via md5 must be accepted: %v", err)
	}
	conn.Close(ctx)
	ss, _ := e.st.ListSessions(context.Background(), 10)
	if len(ss) != 2 || ss[0].PasswordSeen != "tok3n" || !strings.HasPrefix(ss[1].PasswordSeen, "<md5") {
		t.Fatalf("sessions = %+v", ss)
	}
}

func TestGarbageAndTimeouts(t *testing.T) {
	e := start(t, &mysqlhp.Server{}, &pghp.Server{})
	// Garbage to both ports must be recorded and closed, never crash.
	for _, addr := range []string{e.mysqlAddr, e.pgAddr} {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = c.Write([]byte("GET / HTTP/1.0\r\n\r\n"))
		_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
		buf := make([]byte, 4096)
		_, _ = c.Read(buf)
		c.Close()
	}
	time.Sleep(100 * time.Millisecond)
	ss, _ := e.st.ListSessions(context.Background(), 10)
	if len(ss) != 2 {
		t.Fatalf("sessions = %d", len(ss))
	}
	if !strings.Contains(e.logs.String(), `"event":"sql_honeypot_touch"`) {
		t.Fatalf("touch line missing")
	}
}

func TestDashboard(t *testing.T) {
	e := start(t, &mysqlhp.Server{}, &pghp.Server{})
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, fmt.Sprintf("postgres://scan:x@%s/postgres?sslmode=disable", e.pgAddr))
	if err != nil {
		t.Fatal(err)
	}
	conn.Close(ctx)
	e.waitSession(t, "postgres")

	h := web.Handler(e.st, web.Config{AdminUser: "admin", AdminPassword: "pw", MySQLPort: 3306, PGPort: 5432})
	srv := httptest.NewServer(h)
	defer srv.Close()
	get := func(path string, auth bool) (*http.Response, string) {
		req, _ := http.NewRequest("GET", srv.URL+path, nil)
		if auth {
			req.SetBasicAuth("admin", "pw")
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		var b bytes.Buffer
		_, _ = b.ReadFrom(resp.Body)
		resp.Body.Close()
		return resp, b.String()
	}
	if r, _ := get("/", false); r.StatusCode != 401 {
		t.Fatalf("dashboard without auth = %d", r.StatusCode)
	}
	if r, body := get("/", true); r.StatusCode != 200 || !strings.Contains(body, "scan") {
		t.Fatalf("dashboard = %d %q", r.StatusCode, body)
	}
	r, body := get("/api/sessions", true)
	var ss []store.Session
	if r.StatusCode != 200 || json.Unmarshal([]byte(body), &ss) != nil || len(ss) != 1 || ss[0].Username != "scan" {
		t.Fatalf("api = %d %s", r.StatusCode, body)
	}
	if r, body := get(fmt.Sprintf("/sessions/%d", ss[0].ID), true); r.StatusCode != 200 || !strings.Contains(body, "startup") {
		t.Fatalf("session page = %d", r.StatusCode)
	}
	if r, body := get("/metrics", false); r.StatusCode != 200 || !strings.Contains(body, `honeypot_sessions_total{proto="postgres"}`) {
		t.Fatalf("metrics = %d %s", r.StatusCode, body)
	}
	if r, _ := get("/api/live", false); r.StatusCode != 200 {
		t.Fatalf("live = %d", r.StatusCode)
	}
	if r, _ := get("/api/health", false); r.StatusCode != 200 {
		t.Fatalf("health = %d", r.StatusCode)
	}
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

func asMySQLErr(err error, target **mysqldrv.MySQLError) bool {
	for err != nil {
		if e, ok := err.(*mysqldrv.MySQLError); ok {
			*target = e
			return true
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}

func asPgErr(err error, target **pgconn.PgError) bool {
	for err != nil {
		if e, ok := err.(*pgconn.PgError); ok {
			*target = e
			return true
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}
