package store

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"
)

// Memory keeps the last maxSessions sessions in RAM. Used when DATABASE_URL is empty.
type Memory struct {
	mu          sync.Mutex
	nextID      int64
	nextEventID int64
	sessions    []*Session // oldest first
	events      map[int64][]Event
	maxSessions int
}

// NewMemory returns an in-memory store keeping at most max sessions (default 5000).
func NewMemory(max int) *Memory {
	if max <= 0 {
		max = 5000
	}
	return &Memory{events: map[int64][]Event{}, maxSessions: max}
}

func (m *Memory) StartSession(_ context.Context, s *Session) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.nextID++
	s.ID = m.nextID
	cp := *s
	m.sessions = append(m.sessions, &cp)
	if len(m.sessions) > m.maxSessions {
		old := m.sessions[0]
		delete(m.events, old.ID)
		m.sessions = m.sessions[1:]
	}
	return nil
}

func (m *Memory) find(id int64) *Session {
	for i := len(m.sessions) - 1; i >= 0; i-- {
		if m.sessions[i].ID == id {
			return m.sessions[i]
		}
	}
	return nil
}

func (m *Memory) UpdateSession(_ context.Context, s *Session) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cur := m.find(s.ID)
	if cur == nil {
		return errors.New("session not found")
	}
	cp := *s
	*cur = cp
	return nil
}

func (m *Memory) AddEvent(_ context.Context, e *Event) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.nextEventID++
	e.ID = m.nextEventID
	if e.TS.IsZero() {
		e.TS = time.Now()
	}
	m.events[e.SessionID] = append(m.events[e.SessionID], *e)
	return nil
}

func (m *Memory) ListSessions(_ context.Context, limit int) ([]Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if limit <= 0 || limit > len(m.sessions) {
		limit = len(m.sessions)
	}
	out := make([]Session, 0, limit)
	for i := len(m.sessions) - 1; i >= 0 && len(out) < limit; i-- {
		out = append(out, *m.sessions[i])
	}
	return out, nil
}

func (m *Memory) GetSession(_ context.Context, id int64) (*Session, []Event, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.find(id)
	if s == nil {
		return nil, nil, ErrNotFound
	}
	cp := *s
	ev := append([]Event(nil), m.events[id]...)
	return &cp, ev, nil
}

// ErrNotFound is returned by GetSession for unknown ids.
var ErrNotFound = errors.New("not found")

func (m *Memory) Stats(_ context.Context) (*Stats, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	st := &Stats{ByProto: map[string]int64{}}
	ips, users, pwds, queries := map[string]int64{}, map[string]int64{}, map[string]int64{}, map[string]int64{}
	countries, asns := map[string]int64{}, map[string]int64{}
	cut := time.Now().Add(-24 * time.Hour)
	for _, s := range m.sessions {
		st.Total++
		st.ByProto[s.Proto]++
		if s.StartedAt.After(cut) {
			st.Last24h++
		}
		ips[s.RemoteIP]++
		if s.Country != "" {
			countries[s.Country]++
		}
		if s.ASN != 0 {
			asns[fmt.Sprintf("AS%d %s", s.ASN, s.ASOrg)]++
		}
		if s.Username != "" || s.PasswordSeen != "" {
			st.WithAuth++
			users[s.Username]++
			pwds[s.PasswordSeen]++
		}
		for _, e := range m.events[s.ID] {
			if e.Kind == "query" {
				if q, ok := e.Payload["sql"].(string); ok {
					queries[q]++
				}
			}
		}
	}
	st.TopIPs = topN(ips, 10)
	st.TopCountries = topN(countries, 10)
	st.TopASNs = topN(asns, 10)
	st.TopUsernames = topN(users, 10)
	st.TopPasswords = topN(pwds, 10)
	st.TopQueries = topN(queries, 15)
	return st, nil
}

func topN(m map[string]int64, n int) []Count {
	out := make([]Count, 0, len(m))
	for k, v := range m {
		out = append(out, Count{Value: k, N: v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].N != out[j].N {
			return out[i].N > out[j].N
		}
		return out[i].Value < out[j].Value
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}

func (m *Memory) Ping(context.Context) error { return nil }
func (m *Memory) Close()                     {}
