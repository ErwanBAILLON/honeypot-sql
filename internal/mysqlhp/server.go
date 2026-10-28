package mysqlhp

import (
	"bytes"
	"context"
	"crypto/rand"
	"sync/atomic"

	"github.com/ErwanBAILLON/honeypot-sql/internal/fakedb"
	"github.com/ErwanBAILLON/honeypot-sql/internal/hpcore"
)

// Server is the MySQL protocol handler.
type Server struct {
	Version string // e.g. "8.0.36"
	// Passwords, when non-empty, is the honeytoken list: only these are accepted
	// (mysql_native_password hash compared). Empty = accept everything.
	Passwords []string
	connID    atomic.Uint32
}

// Proto implements hpcore.Handler.
func (s *Server) Proto() string { return "mysql" }

func (s *Server) version() string {
	if s.Version == "" {
		return "8.0.36"
	}
	return s.Version
}

// Handle runs one client session.
func (s *Server) Handle(ctx context.Context, c *hpcore.Session) {
	var salt [20]byte
	if _, err := rand.Read(salt[:]); err != nil {
		return
	}
	// Salt bytes must be non-zero and printable-ish like a real server.
	for i := range salt {
		salt[i] = 0x21 + salt[i]%0x5e
	}
	hs := Handshake{ServerVersion: s.version(), ConnectionID: s.connID.Add(1) + 100, Salt: salt,
		Capabilities: ServerCapabilities, CharSet: 0xff, Status: statusAutocommit, AuthPlugin: "mysql_native_password"}
	if err := WritePacket(c, 0, hs.Encode()); err != nil {
		return
	}
	seq, payload, err := ReadPacket(c, c.Limits.MaxPacket)
	if err != nil {
		c.Event("error", map[string]any{"stage": "handshake_response", "err": err.Error()})
		return
	}
	resp, err := DecodeHandshakeResponse(payload)
	if err != nil {
		c.Event("error", map[string]any{"stage": "handshake_response", "err": err.Error(), "raw": hpcore.BlobHex(payload)})
		_ = WritePacket(c, seq+1, ErrPacket(1043, "08S01", "Bad handshake"))
		return
	}
	info := map[string]any{
		"capabilities": CapabilityNames(resp.Capabilities), "capability_flags": resp.Capabilities,
		"max_packet_size": resp.MaxPacketSize, "charset": resp.CharSet, "protocol41": resp.Protocol41,
	}
	if resp.SSLRequest {
		// We never advertised SSL; the client insists. Record and refuse like a server without TLS.
		info["ssl_request"] = true
		c.ClientInfo(info)
		c.Event("handshake", map[string]any{"ssl_request": true})
		_ = WritePacket(c, seq+1, ErrPacket(3159, "HY000", "Connections using insecure transport are prohibited while --require_secure_transport=OFF."))
		return
	}
	if len(resp.Attrs) > 0 {
		info["connect_attrs"] = hpcore.TrimMap(resp.Attrs)
	}
	info["auth_plugin"] = resp.AuthPlugin
	c.ClientInfo(info)
	c.Event("handshake", map[string]any{"username": resp.Username, "database": resp.Database, "auth_plugin": resp.AuthPlugin, "auth_response": hpcore.BlobHex(resp.AuthResponse)})

	authResp := resp.AuthResponse
	if !resp.Protocol41 {
		c.Credentials(resp.Username, resp.Database, "", map[string]any{"auth_response_hex": hpcore.BlobHex(authResp), "auth_plugin": "mysql_old_password"})
		_ = WritePacket(c, seq+1, ErrPacket(1251, "08004", "Client does not support authentication protocol requested by server; consider upgrading MySQL client"))
		return
	}
	if resp.AuthPlugin != "" && resp.AuthPlugin != "mysql_native_password" {
		// caching_sha2_password & co: ask for native, a real 8.0 server does this too.
		seq++
		if err := WritePacket(c, seq, AuthSwitchRequest(salt)); err != nil {
			return
		}
		var p []byte
		seq, p, err = ReadPacket(c, c.Limits.MaxPacket)
		if err != nil {
			c.Credentials(resp.Username, resp.Database, "", map[string]any{"auth_response_hex": hpcore.BlobHex(authResp), "auth_switch": "no_reply"})
			return
		}
		authResp = p
	}

	// Find the plaintext password when it is a known honeytoken, or the empty password.
	password, matched := s.matchPassword(authResp, salt)
	extra := map[string]any{"auth_response_hex": hpcore.BlobHex(authResp), "password_matched": matched}
	if matched && password == "" {
		extra["empty_password"] = true
	}
	c.Credentials(resp.Username, resp.Database, password, extra)

	if len(s.Passwords) > 0 && !matched {
		_ = WritePacket(c, seq+1, ErrPacket(1045, "28000", "Access denied for user '"+resp.Username+"'@'"+c.Rec.RemoteIP+"' (using password: "+yesNo(len(authResp) > 0)+")"))
		return
	}
	if err := WritePacket(c, seq+1, OKPacket(0, "")); err != nil {
		return
	}
	s.commandLoop(ctx, c, resp)
}

func yesNo(b bool) string {
	if b {
		return "YES"
	}
	return "NO"
}

// matchPassword returns the plaintext when authResp equals the hash of a
// honeytoken (or is empty: empty password). matched is true in those cases.
func (s *Server) matchPassword(authResp []byte, salt [20]byte) (string, bool) {
	if len(authResp) == 0 {
		return "", true
	}
	for _, p := range s.Passwords {
		if bytes.Equal(NativePasswordScramble(p, salt), authResp) {
			return p, true
		}
	}
	// Common passwords: lets the dashboard show the plaintext for the usual suspects.
	for _, p := range commonPasswords {
		if bytes.Equal(NativePasswordScramble(p, salt), authResp) {
			return p, len(s.Passwords) == 0
		}
	}
	return "<sha1:" + hpcore.BlobHex(authResp) + ">", false
}

var commonPasswords = []string{"root", "password", "123456", "mysql", "admin", "toor", "test", "12345678", "1234", "root123",
	"Password1", "P@ssw0rd", "qwerty", "123123", "111111", "mysql123", "admin123", "pass", "secret", "changeme", "letmein"}

func (s *Server) commandLoop(ctx context.Context, c *hpcore.Session, resp *HandshakeResponse) {
	db := resp.Database
	for ctx.Err() == nil {
		_, payload, err := ReadPacket(c, c.Limits.MaxPacket)
		if err != nil {
			return
		}
		if len(payload) == 0 {
			_ = WritePacket(c, 1, ErrPacket(1835, "HY000", "Malformed communication packet."))
			return
		}
		c.Stall() // tarpit: hold the client between its command and our reply (no-op when disabled)
		cmd, arg := payload[0], payload[1:]
		switch cmd {
		case comQuit:
			c.Event("quit", nil)
			return
		case comPing:
			c.Event("ping", nil)
			if err := WritePacket(c, 1, OKPacket(0, "")); err != nil {
				return
			}
		case comInitDB:
			db = string(arg)
			if !c.Query("USE " + db) {
				return
			}
			if err := WritePacket(c, 1, OKPacket(0, "")); err != nil {
				return
			}
		case comQuery:
			sql := string(arg)
			if !c.Query(sql) {
				_ = WritePacket(c, 1, ErrPacket(1040, "08004", "Too many connections"))
				return
			}
			res := fakedb.Answer(fakedb.MySQL, sql, fakedb.Env{User: resp.Username, Database: db, RemoteIP: c.Rec.RemoteIP, Version: s.version()})
			if err := s.writeResult(c, res); err != nil {
				return
			}
		case comFieldList:
			if err := WritePacket(c, 1, EOFPacket()); err != nil {
				return
			}
		case comStatistics:
			if err := WritePacket(c, 1, []byte("Uptime: 1823441  Threads: 2  Questions: 94812  Slow queries: 0  Opens: 213  Flush tables: 3  Open tables: 132  Queries per second avg: 0.051")); err != nil {
				return
			}
		case comStmtPrepare:
			sql := string(arg)
			if !c.Query("PREPARE " + sql) {
				return
			}
			// Prepared statements are not emulated: a syntax error keeps most drivers trying the text protocol.
			if err := WritePacket(c, 1, ErrPacket(1295, "HY000", "This command is not supported in the prepared statement protocol yet")); err != nil {
				return
			}
		case comStmtClose:
			// no response expected
		case comResetConn:
			if err := WritePacket(c, 1, OKPacket(0, "")); err != nil {
				return
			}
		default:
			c.Event("command", map[string]any{"cmd": cmd, "arg": hexBytes(truncate(arg, 256))})
			if err := WritePacket(c, 1, ErrPacket(1047, "08S01", "Unknown command")); err != nil {
				return
			}
		}
	}
}

func truncate(b []byte, n int) []byte {
	if len(b) > n {
		return b[:n]
	}
	return b
}

func (s *Server) writeResult(c *hpcore.Session, res fakedb.Result) error {
	if res.Err != nil {
		return WritePacket(c, 1, ErrPacket(uint16(res.Err.Code), res.Err.SQLState, res.Err.Message))
	}
	if len(res.Cols) == 0 {
		return WritePacket(c, 1, OKPacket(0, ""))
	}
	var seq byte = 1
	var buf bytes.Buffer
	_ = WritePacket(&buf, seq, appendLenenc(nil, uint64(len(res.Cols))))
	for _, col := range res.Cols {
		seq++
		_ = WritePacket(&buf, seq, ColumnDef(col))
	}
	seq++
	_ = WritePacket(&buf, seq, EOFPacket())
	for _, row := range res.Rows {
		seq++
		_ = WritePacket(&buf, seq, RowPacket(row))
	}
	seq++
	_ = WritePacket(&buf, seq, EOFPacket())
	_, err := c.Write(buf.Bytes())
	return err
}
