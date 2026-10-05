// Package hplog writes one JSON line per security-relevant event to stdout
// (consumed by CrowdSec through the container log) and keeps Prometheus
// counters served on /metrics. Operational logs go to stderr via log.
package hplog

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

var (
	mu  sync.Mutex
	out io.Writer = os.Stdout
)

// SetOutput redirects event lines (tests).
func SetOutput(w io.Writer) {
	mu.Lock()
	defer mu.Unlock()
	out = w
}

// Emit writes {"ts":..., "event":<event>, ...fields} as a single JSON line.
// Field values must be JSON-encodable. The password is truncated by callers.
func Emit(event string, fields map[string]any) {
	rec := make(map[string]any, len(fields)+2)
	for k, v := range fields {
		rec[k] = v
	}
	rec["ts"] = time.Now().UTC().Format(time.RFC3339Nano)
	rec["event"] = event
	b, err := json.Marshal(rec)
	if err != nil {
		return
	}
	mu.Lock()
	defer mu.Unlock()
	_, _ = out.Write(append(b, '\n'))
}

// Counters (Prometheus text format on /metrics).
type counter struct {
	name, help string
	vals       sync.Map // label value -> *atomic.Int64
}

func (c *counter) Inc(label string) {
	v, _ := c.vals.LoadOrStore(label, new(atomic.Int64))
	v.(*atomic.Int64).Add(1)
}

var (
	Sessions = &counter{name: "honeypot_sessions_total", help: "TCP sessions accepted, by protocol."}
	Auth     = &counter{name: "honeypot_auth_attempts_total", help: "Credential attempts recorded, by protocol."}
	Queries  = &counter{name: "honeypot_queries_total", help: "Queries received, by protocol."}
	Rejected = &counter{name: "honeypot_rejected_total", help: "Connections dropped because of the concurrency cap, by protocol."}
	Active   atomic.Int64
)

// WriteMetrics renders all counters in Prometheus text exposition format.
func WriteMetrics(w io.Writer) {
	for _, c := range []*counter{Sessions, Auth, Queries, Rejected} {
		fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s counter\n", c.name, c.help, c.name)
		var keys []string
		c.vals.Range(func(k, _ any) bool { keys = append(keys, k.(string)); return true })
		sort.Strings(keys)
		for _, k := range keys {
			v, _ := c.vals.Load(k)
			fmt.Fprintf(w, "%s{proto=%q} %d\n", c.name, k, v.(*atomic.Int64).Load())
		}
	}
	fmt.Fprintf(w, "# HELP honeypot_active_connections Open honeypot connections.\n# TYPE honeypot_active_connections gauge\nhoneypot_active_connections %d\n", Active.Load())
}
