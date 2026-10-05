package hpcore

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestBlobHexBounded(t *testing.T) {
	small := []byte("abc")
	if got := BlobHex(small); got != "616263" {
		t.Fatalf("small = %q", got)
	}
	big := bytes.Repeat([]byte{0xab}, 900_000)
	got := BlobHex(big)
	if len(got) > 2*BlobKeep+120 {
		t.Fatalf("oversized blob not bounded: len=%d", len(got))
	}
	if !strings.Contains(got, "len=900000") || !strings.Contains(got, "sha256=") {
		t.Fatalf("missing summary: %q", got[len(got)-100:])
	}
}

func TestTrimMapBounded(t *testing.T) {
	m := map[string]string{}
	for i := 0; i < 200; i++ {
		m[fmt.Sprintf("k%03d", i)] = strings.Repeat("v", 10_000)
	}
	out := TrimMap(m)
	if len(out) != MapMaxKeys+1 || out["_dropped"] != "136" {
		t.Fatalf("keys=%d dropped=%q", len(out), out["_dropped"])
	}
	for k, v := range out {
		if len(k) > MapMaxLen || len(v) > MapMaxLen {
			t.Fatalf("entry %q too long (%d)", k, len(v))
		}
	}
	if TrimMap(nil) != nil {
		t.Fatal("nil must stay nil")
	}
}

func TestBoundPayload(t *testing.T) {
	p := map[string]any{"a": 1, "blob": strings.Repeat("x", 100_000)}
	out := BoundPayload(p, EventMaxJSON)
	b, _ := json.Marshal(out)
	if len(b) > 1024 || out["_truncated"] != true {
		t.Fatalf("not bounded: %s", b)
	}
	small := map[string]any{"a": 1}
	if got := BoundPayload(small, EventMaxJSON); got["a"] != 1 || len(got) != 1 {
		t.Fatalf("small payload altered: %v", got)
	}
}
