// Package web serves the dashboard, the JSON API, the probes and /metrics.
package web

import (
	"context"
	"crypto/subtle"
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"git.ebaillon.fr/infra/honeypot-sql/internal/hplog"
	"git.ebaillon.fr/infra/honeypot-sql/internal/store"
)

//go:embed templates/*.html
var tmplFS embed.FS

// Config for the web server.
type Config struct {
	AdminUser     string
	AdminPassword string
	MySQLPort     int // displayed in the header
	PGPort        int
}

// Handler builds the HTTP mux.
func Handler(st store.Store, cfg Config) http.Handler {
	funcs := template.FuncMap{
		"ago": func(t time.Time) string {
			d := time.Since(t).Round(time.Second)
			switch {
			case d < time.Minute:
				return fmt.Sprintf("%ds", int(d.Seconds()))
			case d < time.Hour:
				return fmt.Sprintf("%dmin", int(d.Minutes()))
			case d < 48*time.Hour:
				return fmt.Sprintf("%dh", int(d.Hours()))
			}
			return fmt.Sprintf("%dj", int(d.Hours()/24))
		},
		"dur": func(s store.Session) string {
			if s.EndedAt == nil {
				return "en cours"
			}
			return s.EndedAt.Sub(s.StartedAt).Round(time.Millisecond).String()
		},
		"json": func(v any) string {
			b, _ := json.MarshalIndent(v, "", "  ")
			return string(b)
		},
		"short": func(s string) string {
			if len(s) > 90 {
				return s[:90] + "…"
			}
			return s
		},
		"fmtTime": func(t time.Time) string { return t.Local().Format("2006-01-02 15:04:05") },
	}
	tmpl := template.Must(template.New("").Funcs(funcs).ParseFS(tmplFS, "templates/*.html"))

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/live", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("GET /api/health", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()
		if err := st.Ping(ctx); err != nil {
			http.Error(w, "store: "+err.Error(), http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		hplog.WriteMetrics(w)
	})

	auth := basicAuth(cfg.AdminUser, cfg.AdminPassword)
	mux.Handle("GET /{$}", auth(func(w http.ResponseWriter, r *http.Request) {
		stats, err := st.Stats(r.Context())
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		sessions, err := st.ListSessions(r.Context(), 50)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		render(w, tmpl, "index.html", map[string]any{"Stats": stats, "Sessions": sessions, "Cfg": cfg, "Now": time.Now()})
	}))
	mux.Handle("GET /sessions/{id}", auth(func(w http.ResponseWriter, r *http.Request) {
		id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		s, evs, err := st.GetSession(r.Context(), id)
		if err == store.ErrNotFound {
			http.NotFound(w, r)
			return
		}
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		render(w, tmpl, "session.html", map[string]any{"S": s, "Events": evs, "Cfg": cfg})
	}))
	mux.Handle("GET /api/sessions", auth(func(w http.ResponseWriter, r *http.Request) {
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		if limit <= 0 || limit > 1000 {
			limit = 100
		}
		sessions, err := st.ListSessions(r.Context(), limit)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		if sessions == nil {
			sessions = []store.Session{}
		}
		writeJSON(w, sessions)
	}))
	mux.Handle("GET /api/sessions/{id}", auth(func(w http.ResponseWriter, r *http.Request) {
		id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		s, evs, err := st.GetSession(r.Context(), id)
		if err == store.ErrNotFound {
			http.NotFound(w, r)
			return
		}
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		writeJSON(w, map[string]any{"session": s, "events": evs})
	}))
	mux.Handle("GET /api/stats", auth(func(w http.ResponseWriter, r *http.Request) {
		stats, err := st.Stats(r.Context())
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		writeJSON(w, stats)
	}))
	return securityHeaders(mux)
}

func render(w http.ResponseWriter, t *template.Template, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := t.ExecuteTemplate(w, name, data); err != nil {
		log.Printf("web: render %s: %v", name, err)
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; img-src data:; form-action 'self'")
		h.Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

// basicAuth protects the dashboard. Empty credentials = refuse everything
// (fail closed): the dashboard shows attacker passwords.
func basicAuth(user, pass string) func(http.HandlerFunc) http.Handler {
	return func(next http.HandlerFunc) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			u, p, ok := r.BasicAuth()
			if user == "" || pass == "" || !ok ||
				subtle.ConstantTimeCompare([]byte(u), []byte(user)) != 1 ||
				subtle.ConstantTimeCompare([]byte(p), []byte(pass)) != 1 {
				w.Header().Set("WWW-Authenticate", `Basic realm="honeypot-sql", charset="UTF-8"`)
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			next(w, r)
		})
	}
}

// Serve runs the HTTP server until ctx is done.
func Serve(ctx context.Context, addr string, h http.Handler) error {
	srv := &http.Server{Addr: addr, Handler: h, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second}
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
