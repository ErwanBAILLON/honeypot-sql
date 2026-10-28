package hpcore

import (
	"context"
	"testing"

	"github.com/ErwanBAILLON/honeypot-sql/internal/store"
)

func TestCheckReplayRecordsAHit(t *testing.T) {
	st := store.NewMemory(0)
	// A credential handed out in session 1's fake data.
	_ = st.IssueToken(context.Background(), &store.CanaryToken{Token: "svc-token-abcdef", Kind: "credential", SessionID: 1, Label: "users.secret"})

	// Later, a different client presents it as a login.
	s := &Session{Store: st, ctx: context.Background()}
	s.Rec = store.Session{Proto: "postgres", RemoteIP: "198.51.100.4", Country: "NL"}
	s.checkReplay("svc-token-abcdef", "password")

	cs, _ := st.Canaries(context.Background(), 10)
	if len(cs) != 1 || cs[0].Hits != 1 {
		t.Fatalf("expected the replay to be recorded, got %+v", cs)
	}
	if cs[0].LastHitChannel != "credential_replay" || cs[0].LastHitIP != "198.51.100.4" {
		t.Errorf("replay hit wrong: %+v", cs[0])
	}
}

func TestCheckReplayIgnoresShortOrUnknownValues(t *testing.T) {
	st := store.NewMemory(0)
	s := &Session{Store: st, ctx: context.Background()}
	s.Rec = store.Session{Proto: "mysql", RemoteIP: "198.51.100.4"}
	s.checkReplay("root", "password")               // too short / common
	s.checkReplay("never-issued-token", "password") // unknown
	cs, _ := st.Canaries(context.Background(), 10)
	if len(cs) != 0 {
		t.Fatalf("no hit expected, got %+v", cs)
	}
}
