package hpcore

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
)

// Storage bounds. A client may send up to Limits.MaxPacket (1 MiB) per
// packet; nothing of that size is ever persisted as is. Hex doubles the
// size and the same blob used to land in three places, so one 900 KB auth
// blob cost ~5 MB of shared Postgres.
const (
	BlobKeep      = 256      // bytes of a client blob kept verbatim (hex-encoded)
	MapMaxKeys    = 64       // connect attrs / startup params kept
	MapMaxLen     = 256      // per key and per value
	EventMaxJSON  = 16 << 10 // an event payload larger than this is replaced by a summary
	ClientInfoMax = 32 << 10 // same for the session's client_info blob
)

// BlobHex returns the hex of b when it fits BlobKeep bytes, otherwise the hex
// of its prefix followed by the total length and a sha256 so two sessions
// sending the same oversized blob remain comparable.
func BlobHex(b []byte) string {
	if len(b) <= BlobKeep {
		return hex.EncodeToString(b)
	}
	sum := sha256.Sum256(b)
	return fmt.Sprintf("%s...[len=%d sha256=%s]", hex.EncodeToString(b[:BlobKeep]), len(b), hex.EncodeToString(sum[:]))
}

// TrimMap bounds a client-supplied string map: at most MapMaxKeys entries
// (smallest keys first, deterministic) and MapMaxLen bytes per key and value.
// Dropped entries are counted under "_dropped".
func TrimMap(m map[string]string) map[string]string {
	if m == nil {
		return nil
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make(map[string]string, len(keys))
	dropped := 0
	for i, k := range keys {
		if i >= MapMaxKeys {
			dropped++
			continue
		}
		out[trim(k, MapMaxLen)] = trim(m[k], MapMaxLen)
	}
	if dropped > 0 {
		out["_dropped"] = fmt.Sprintf("%d", dropped)
	}
	return out
}

// BoundPayload replaces a payload whose JSON exceeds max bytes by a summary.
// Last line of defence: protocol handlers are expected to bound their fields
// before reaching here.
func BoundPayload(payload map[string]any, max int) map[string]any {
	if payload == nil {
		return nil
	}
	b, err := json.Marshal(payload)
	if err != nil || len(b) <= max {
		return payload
	}
	sum := sha256.Sum256(b)
	keys := make([]string, 0, len(payload))
	for k := range payload {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return map[string]any{"_truncated": true, "json_len": len(b), "sha256": hex.EncodeToString(sum[:]), "keys": keys}
}
