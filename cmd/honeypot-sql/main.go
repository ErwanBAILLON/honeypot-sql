// Command honeypot-sql is a low-interaction MySQL + PostgreSQL honeypot with a
// small dashboard. Subcommands: serve (default), stats.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/ErwanBAILLON/honeypot-sql/internal/geoip"
	"github.com/ErwanBAILLON/honeypot-sql/internal/hpcore"
	"github.com/ErwanBAILLON/honeypot-sql/internal/mysqlhp"
	"github.com/ErwanBAILLON/honeypot-sql/internal/pghp"
	"github.com/ErwanBAILLON/honeypot-sql/internal/store"
	"github.com/ErwanBAILLON/honeypot-sql/internal/web"
)

func env(key, def string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return def
}

func envInt(key string, def int) int {
	if v, err := strconv.Atoi(env(key, "")); err == nil {
		return v
	}
	return def
}

func envDur(key string, def time.Duration) time.Duration {
	if v, err := time.ParseDuration(env(key, "")); err == nil {
		return v
	}
	return def
}

func main() {
	log.SetOutput(os.Stderr) // stdout is reserved for JSON event lines (CrowdSec)
	log.SetFlags(log.LstdFlags | log.LUTC)
	cmd := "serve"
	args := os.Args[1:]
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		cmd, args = args[0], args[1:]
	}
	var err error
	switch cmd {
	case "serve":
		err = serve(args)
	case "stats":
		err = stats(args)
	case "version":
		fmt.Println("honeypot-sql", version)
	default:
		fmt.Fprintf(os.Stderr, "usage: honeypot-sql [serve|stats|version] [flags]\n")
		os.Exit(2)
	}
	if err != nil {
		log.Fatal(err)
	}
}

var version = "dev"

func openStore(ctx context.Context) (store.Store, error) {
	url := os.Getenv("DATABASE_URL")
	if url == "" {
		log.Printf("DATABASE_URL empty: using in-memory store")
		return store.NewMemory(0), nil
	}
	var last error
	for i := 0; i < 10; i++ {
		st, err := store.NewPostgres(ctx, url)
		if err == nil {
			return st, nil
		}
		last = err
		log.Printf("postgres not ready (%v), retrying", err)
		select {
		case <-time.After(3 * time.Second):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return nil, last
}

func serve(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	mysqlAddr := fs.String("mysql", env("HONEYPOT_MYSQL_ADDR", ":3306"), "MySQL listen address (empty = disabled)")
	pgAddr := fs.String("pg", env("HONEYPOT_PG_ADDR", ":5432"), "PostgreSQL listen address (empty = disabled)")
	httpAddr := fs.String("http", env("HONEYPOT_HTTP_ADDR", ":8080"), "dashboard listen address")
	mysqlVersion := fs.String("mysql-version", env("HONEYPOT_MYSQL_VERSION", "8.0.36"), "advertised MySQL version")
	pgVersion := fs.String("pg-version", env("HONEYPOT_PG_VERSION", "16.3"), "advertised PostgreSQL version")
	pgMD5 := fs.Bool("pg-md5", env("HONEYPOT_PG_AUTH", "cleartext") == "md5", "ask md5 instead of cleartext password")
	passwords := fs.String("passwords", env("HONEYPOT_PASSWORDS", ""), "comma-separated honeytoken passwords; empty = accept any credential")
	maxConns := fs.Int("max-conns", envInt("HONEYPOT_MAX_CONNS", 500), "max concurrent connections per listener")
	readTimeout := fs.Duration("read-timeout", 30*time.Second, "per-read timeout")
	sessionMax := fs.Duration("session-max", 10*time.Minute, "max session duration")
	tarpit := fs.Duration("tarpit", envDur("HONEYPOT_TARPIT", 0), "delay before each reply to keep the attacker engaged (0 = off); capped by -session-max")
	ip2asn := fs.String("ip2asn", env("HONEYPOT_IP2ASN", ""), "path to an ip2asn table (iptoasn.com TSV, optionally .gz) for offline country/ASN attribution; empty = off")
	if err := fs.Parse(args); err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	st, err := openStore(ctx)
	if err != nil {
		return err
	}
	defer st.Close()

	var pwList []string
	for _, p := range strings.Split(*passwords, ",") {
		if p = strings.TrimSpace(p); p != "" {
			pwList = append(pwList, p)
		}
	}
	lim := hpcore.Limits{MaxConns: *maxConns, ReadTimeout: *readTimeout, SessionMax: *sessionMax, Tarpit: *tarpit}
	if *ip2asn != "" {
		db, err := geoip.Load(*ip2asn)
		if err != nil {
			return fmt.Errorf("load ip2asn %q: %w", *ip2asn, err)
		}
		lim.Geo = db
		log.Printf("ip2asn attribution on: %d ranges from %s", db.Len(), *ip2asn)
	}
	if *tarpit > 0 {
		log.Printf("tarpit on: %s before each reply (capped by session-max %s)", *tarpit, *sessionMax)
	}

	g, gctx := errgroup.WithContext(ctx)
	if *mysqlAddr != "" {
		ln, err := net.Listen("tcp", *mysqlAddr)
		if err != nil {
			return fmt.Errorf("mysql listen: %w", err)
		}
		log.Printf("mysql honeypot on %s (version %s)", ln.Addr(), *mysqlVersion)
		g.Go(func() error {
			return hpcore.Serve(gctx, ln, &mysqlhp.Server{Version: *mysqlVersion, Passwords: pwList}, st, lim)
		})
	}
	if *pgAddr != "" {
		ln, err := net.Listen("tcp", *pgAddr)
		if err != nil {
			return fmt.Errorf("pg listen: %w", err)
		}
		log.Printf("postgres honeypot on %s (version %s, auth %s)", ln.Addr(), *pgVersion, map[bool]string{true: "md5", false: "cleartext"}[*pgMD5])
		g.Go(func() error {
			return hpcore.Serve(gctx, ln, &pghp.Server{Version: *pgVersion, AuthMD5: *pgMD5, Passwords: pwList}, st, lim)
		})
	}
	cfg := web.Config{AdminUser: os.Getenv("ADMIN_USER"), AdminPassword: os.Getenv("ADMIN_PASSWORD"), MySQLPort: portOf(*mysqlAddr), PGPort: portOf(*pgAddr)}
	if cfg.AdminUser == "" || cfg.AdminPassword == "" {
		log.Printf("WARNING: ADMIN_USER/ADMIN_PASSWORD unset, dashboard refuses every request")
	}
	log.Printf("dashboard on %s", *httpAddr)
	g.Go(func() error { return web.Serve(gctx, *httpAddr, web.Handler(st, cfg)) })
	return g.Wait()
}

func portOf(addr string) int {
	_, p, err := net.SplitHostPort(addr)
	if err != nil {
		return 0
	}
	n, _ := strconv.Atoi(p)
	return n
}

func stats(args []string) error {
	fs := flag.NewFlagSet("stats", flag.ExitOnError)
	asJSON := fs.Bool("json", false, "print JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	st, err := openStore(ctx)
	if err != nil {
		return err
	}
	defer st.Close()
	s, err := st.Stats(ctx)
	if err != nil {
		return err
	}
	if *asJSON {
		b, _ := json.MarshalIndent(s, "", "  ")
		fmt.Println(string(b))
		return nil
	}
	fmt.Printf("sessions: %d (24h: %d, with credentials: %d)\n", s.Total, s.Last24h, s.WithAuth)
	for k, v := range s.ByProto {
		fmt.Printf("  %-9s %d\n", k, v)
	}
	printTop := func(title string, c []store.Count) {
		fmt.Println(title)
		for _, x := range c {
			fmt.Printf("  %6d  %s\n", x.N, x.Value)
		}
	}
	printTop("top ips:", s.TopIPs)
	printTop("top usernames:", s.TopUsernames)
	printTop("top passwords:", s.TopPasswords)
	printTop("top queries:", s.TopQueries)
	return nil
}
