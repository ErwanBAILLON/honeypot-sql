package canary

import (
	"context"
	"testing"

	"github.com/ErwanBAILLON/honeypot-sql/internal/store"
)

func TestMintCapAndStability(t *testing.T) {
	st := store.NewMemory(0)
	m := NewMinter(context.Background(), st, 1, "https://cdn.example/t")

	a := m.Mint("credential", "users.secret")
	b := m.Mint("credential", "users.secret")
	if a == "" || a != b {
		t.Fatalf("same label should give the same value: %q vs %q", a, b)
	}
	if got, _ := st.FindToken(context.Background(), a); got == nil {
		t.Fatal("minted credential token was not recorded")
	}
	u := m.Mint("url", "users.backup_url")
	if u == "" || u[:len("https://cdn.example/t/")] != "https://cdn.example/t/" {
		t.Fatalf("url token %q is not under the beacon base", u)
	}
	// Fill up to the per-session cap; further distinct labels mint nothing.
	for i := 0; i < MaxPerSession+5; i++ {
		m.Mint("credential", string(rune('a'+i))+"_label")
	}
	if n := len(m.issued); n > MaxPerSession {
		t.Fatalf("minted %d tokens, over the cap %d", n, MaxPerSession)
	}
}

func TestURLTokenNeedsBeaconURL(t *testing.T) {
	m := NewMinter(context.Background(), store.NewMemory(0), 1, "")
	if v := m.Mint("url", "x.url"); v != "" {
		t.Fatalf("url token without a beacon URL should be empty, got %q", v)
	}
	if v := m.Mint("credential", "x.cred"); v == "" {
		t.Fatal("credential token should still mint without a beacon URL")
	}
}

func TestNilMinterMintsNothing(t *testing.T) {
	var m *Minter
	if v := m.Mint("credential", "x"); v != "" {
		t.Fatalf("nil minter should mint nothing, got %q", v)
	}
}

func TestTokenFromURL(t *testing.T) {
	for _, tc := range []struct{ path, want string }{
		{"/t/abc123", "abc123"},
		{"/t/abc123/more", "abc123"},
		{"/t/abc123?q=1", "abc123"},
		{"/assets/t/deadbeef", "deadbeef"},
		{"/nope", ""},
		{"/t/", ""},
	} {
		if got := TokenFromURL(tc.path); got != tc.want {
			t.Errorf("TokenFromURL(%q) = %q, want %q", tc.path, got, tc.want)
		}
	}
}
