// Package beacon is the honeypot's "black box": a tiny unauthenticated HTTP
// listener that only ever *receives* pings. When a canary URL planted in the
// fake data is loaded (by an attacker's tooling, a crawler, a preview bot), the
// request lands here; we record who touched it and which session the token was
// handed to, then reply with a blank 1x1 GIF so nothing looks wrong. It opens
// no outbound connection and triggers no action beyond logging.
package beacon

import (
	"context"
	"encoding/hex"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ErwanBAILLON/honeypot-sql/internal/canary"
	"github.com/ErwanBAILLON/honeypot-sql/internal/geoip"
	"github.com/ErwanBAILLON/honeypot-sql/internal/hplog"
	"github.com/ErwanBAILLON/honeypot-sql/internal/store"
)

// a 1x1 transparent GIF, the classic web-bug body
var pixel, _ = hex.DecodeString("47494638396101000100800000000000ffffff21f90401000000002c00000000010001000002024401003b")

// Handler records a hit for every /t/<token> request and returns the pixel.
// geo may be nil (no attribution); st records the hit.
func Handler(st store.Store, geo *geoip.DB) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/t/", func(w http.ResponseWriter, r *http.Request) {
		token := canary.TokenFromURL(r.URL.Path)
		if token != "" {
			record(r, st, geo, token)
		}
		w.Header().Set("Content-Type", "image/gif")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(pixel)
	})
	// Anything else looks like an ordinary empty server.
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	})
	return mux
}

func record(r *http.Request, st store.Store, geo *geoip.DB, token string) {
	ip, portStr, _ := net.SplitHostPort(r.RemoteAddr)
	port, _ := strconv.Atoi(portStr)
	// Behind a reverse proxy the real client is in X-Forwarded-For; keep the
	// socket peer too, in the detail, so nothing is silently trusted.
	detail := map[string]any{"user_agent": trim(r.UserAgent(), 256), "path": trim(r.URL.Path, 256), "peer": r.RemoteAddr}
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		detail["x_forwarded_for"] = trim(xff, 256)
		if first := strings.TrimSpace(strings.Split(xff, ",")[0]); first != "" {
			ip, port = first, 0
		}
	}
	hit := &store.CanaryHit{Token: token, Channel: "http", SourceIP: ip, SourcePort: port, TS: time.Now(), Detail: detail}
	if geo != nil {
		if rec, ok := geo.Lookup(ip); ok {
			hit.Country, hit.ASN, hit.ASOrg = rec.Country, int(rec.ASN), trim(rec.Org, 128)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tok, err := st.FindToken(ctx, token)
	if err == nil {
		detail["issued_to_session"] = tok.SessionID
		detail["kind"] = tok.Kind
		detail["label"] = tok.Label
	}
	if err := st.RecordHit(ctx, hit); err != nil {
		log.Printf("beacon: record hit: %v", err)
		return
	}
	hplog.Emit("sql_honeypot_canary", map[string]any{
		"channel": "http", "token": token, "remote_ip": ip, "country": hit.Country,
		"asn": hit.ASN, "as_org": hit.ASOrg, "known": err == nil,
	})
}

func trim(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// Serve runs the beacon until ctx is done.
func Serve(ctx context.Context, addr string, h http.Handler) error {
	srv := &http.Server{
		Addr: addr, Handler: h,
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second,
		WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10,
	}
	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServe() }()
	select {
	case <-ctx.Done():
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return srv.Shutdown(sctx)
	case err := <-errc:
		if err != nil && !strings.Contains(err.Error(), "Server closed") {
			return err
		}
		return nil
	}
}
