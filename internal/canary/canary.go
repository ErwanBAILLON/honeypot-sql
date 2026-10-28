// Package canary plants unique markers ("canary tokens") in the fake data a
// session is served, so that reuse of that data can be traced back here. Two
// kinds are planted: a credential (seen again when it is replayed as a login
// on our own listeners) and a URL pointing at the beacon (seen again when the
// attacker's tooling loads it). Nothing reaches toward the attacker: a token
// is just a value we hand out and later recognise.
package canary

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log"
	"strings"
	"time"

	"github.com/ErwanBAILLON/honeypot-sql/internal/store"
)

// MaxPerSession caps how many distinct tokens one session can mint, so a bot
// running thousands of queries cannot flood the token store.
const MaxPerSession = 8

// NewToken returns an opaque, URL-safe, hard-to-guess marker.
func NewToken() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// Minter issues and records tokens for one session. It is used from the single
// goroutine that serves the session, so it needs no lock. The zero/nil Minter
// mints nothing, which is how canaries stay off unless a store is wired in.
type Minter struct {
	Store     store.Store
	SessionID int64
	BeaconURL string // base for URL tokens, e.g. "https://host/t/"; empty disables URL tokens
	ctx       context.Context
	issued    map[string]string // label -> value already minted this session
}

// NewMinter builds a Minter bound to a session.
func NewMinter(ctx context.Context, st store.Store, sessionID int64, beaconURL string) *Minter {
	return &Minter{Store: st, SessionID: sessionID, BeaconURL: beaconURL, ctx: ctx, issued: map[string]string{}}
}

// Mint returns the value to embed for (kind, label), recording the token, or ""
// when canaries are off, the per-session cap is reached, or a URL token is
// asked for without a beacon URL. The same label yields the same value within
// a session, so a table rendered twice stays consistent.
func (m *Minter) Mint(kind, label string) string {
	if m == nil || m.Store == nil {
		return ""
	}
	if v, ok := m.issued[label]; ok {
		return v
	}
	if len(m.issued) >= MaxPerSession {
		return ""
	}
	if kind == "url" && m.BeaconURL == "" {
		return ""
	}
	token := NewToken()
	value := token
	if kind == "url" {
		value = strings.TrimRight(m.BeaconURL, "/") + "/" + token
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := m.Store.IssueToken(ctx, &store.CanaryToken{Token: token, Kind: kind, SessionID: m.SessionID, Label: label}); err != nil {
		log.Printf("canary: issue token: %v", err)
		return ""
	}
	m.issued[label] = value
	return value
}

// TokenFromURL extracts the token from a beacon request path "/t/<token>"
// (anything after the token, like a slash or query, is ignored).
func TokenFromURL(path string) string {
	i := strings.Index(path, "/t/")
	if i < 0 {
		return ""
	}
	rest := path[i+3:]
	if j := strings.IndexAny(rest, "/?#"); j >= 0 {
		rest = rest[:j]
	}
	return rest
}
