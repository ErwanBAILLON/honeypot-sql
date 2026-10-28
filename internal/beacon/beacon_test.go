package beacon

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ErwanBAILLON/honeypot-sql/internal/store"
)

func TestBeaconRecordsHitAndReturnsPixel(t *testing.T) {
	st := store.NewMemory(0)
	// A token issued to session 7 in a past "dump".
	_ = st.IssueToken(context.Background(), &store.CanaryToken{Token: "tok-abc", Kind: "url", SessionID: 7, Label: "users.backup_url"})
	srv := httptest.NewServer(Handler(st, nil))
	defer srv.Close()

	req, _ := http.NewRequest("GET", srv.URL+"/t/tok-abc", nil)
	req.Header.Set("User-Agent", "curl/8.1")
	req.Header.Set("X-Forwarded-For", "203.0.113.9, 10.0.0.1")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if ct := resp.Header.Get("Content-Type"); ct != "image/gif" {
		t.Fatalf("content-type = %q, want image/gif", ct)
	}

	cs, _ := st.Canaries(context.Background(), 10)
	if len(cs) != 1 || cs[0].Hits != 1 {
		t.Fatalf("expected 1 canary with 1 hit, got %+v", cs)
	}
	if cs[0].LastHitIP != "203.0.113.9" { // X-Forwarded-For client wins
		t.Errorf("last hit ip = %q, want the XFF client", cs[0].LastHitIP)
	}
	if cs[0].SessionID != 7 || cs[0].LastHitChannel != "http" {
		t.Errorf("hit not linked to the issuing session/channel: %+v", cs[0])
	}
}

func TestBeaconUnknownTokenStillAnswers(t *testing.T) {
	st := store.NewMemory(0)
	srv := httptest.NewServer(Handler(st, nil))
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/t/never-issued")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 { // a bland pixel even for an unknown token
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	cs, _ := st.Canaries(context.Background(), 10)
	if len(cs) != 0 { // the token was never issued, so nothing to list
		t.Fatalf("unknown token should not create a canary row, got %d", len(cs))
	}
}
