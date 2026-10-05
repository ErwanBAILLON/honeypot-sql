package pghp

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"strings"
	"sync/atomic"

	"github.com/ErwanBAILLON/honeypot-sql/internal/fakedb"
	"github.com/ErwanBAILLON/honeypot-sql/internal/hpcore"
)

// Server is the PostgreSQL protocol handler.
type Server struct {
	Version   string // "16.3"
	AuthMD5   bool   // ask md5 instead of cleartext (records only the hash then)
	Passwords []string
	pid       atomic.Uint32
}

// Proto implements hpcore.Handler.
func (s *Server) Proto() string { return "postgres" }

func (s *Server) version() string {
	if s.Version == "" {
		return "16.3"
	}
	return s.Version
}

// Handle runs one client session.
func (s *Server) Handle(ctx context.Context, c *hpcore.Session) {
	var st *Startup
	for i := 0; i < 3; i++ {
		var err error
		st, err = ReadStartup(c)
		if err != nil {
			c.Event("error", map[string]any{"stage": "startup", "err": err.Error()})
			return
		}
		switch st.Protocol {
		case sslRequestCode:
			c.Event("ssl_request", nil)
			c.ClientInfo(map[string]any{"ssl_request": true})
			if _, err := c.Write([]byte{'N'}); err != nil {
				return
			}
			continue
		case gssEncRequest:
			c.Event("gssenc_request", nil)
			if _, err := c.Write([]byte{'N'}); err != nil {
				return
			}
			continue
		case cancelRequest:
			c.Event("cancel_request", nil)
			return
		case protoV3:
		default:
			c.Event("error", map[string]any{"stage": "startup", "protocol": st.Protocol})
			_, _ = c.Write(ErrorResponse("0A000", fmt.Sprintf("unsupported frontend protocol %d.%d: server supports 3.0 to 3.0", st.Protocol>>16, st.Protocol&0xffff)))
			return
		}
		break
	}
	if st == nil || st.Protocol != protoV3 {
		return
	}
	user, db := st.Params["user"], st.Params["database"]
	if db == "" {
		db = user
	}
	params := hpcore.TrimMap(st.Params)
	info := map[string]any{"startup_params": params}
	if v := st.Params["application_name"]; v != "" {
		info["application_name"] = v
	}
	c.ClientInfo(info)
	c.Event("startup", map[string]any{"params": params})

	var salt [4]byte
	_, _ = rand.Read(salt[:])
	authMsg := AuthCleartext()
	if s.AuthMD5 {
		authMsg = AuthMD5(salt)
	}
	if _, err := c.Write(authMsg); err != nil {
		return
	}
	m, err := ReadMessage(c, c.Limits.MaxPacket)
	if err != nil {
		c.Credentials(user, db, "", map[string]any{"password_message": "none", "err": err.Error()})
		return
	}
	if m.Type != 'p' {
		c.Credentials(user, db, "", map[string]any{"password_message": string(m.Type)})
		_, _ = c.Write(ErrorResponse("08P01", "expected password response, got message type "+string(m.Type)))
		return
	}
	pw, _ := parseCString(m.Body)
	matched := len(s.Passwords) == 0
	recorded := pw
	if s.AuthMD5 {
		recorded = "<" + pw + ">"
		for _, p := range s.Passwords {
			if MD5Password(p, user, salt) == pw {
				recorded, matched = p, true
			}
		}
	} else {
		for _, p := range s.Passwords {
			if p == pw {
				matched = true
			}
		}
	}
	c.Credentials(user, db, recorded, map[string]any{"auth_method": map[bool]string{true: "md5", false: "cleartext"}[s.AuthMD5], "password_matched": matched})
	if !matched {
		_, _ = c.Write(ErrorResponse("28P01", fmt.Sprintf("password authentication failed for user \"%s\"", user)))
		return
	}

	var buf bytes.Buffer
	buf.Write(AuthOK())
	for _, kv := range [][2]string{
		{"in_hot_standby", "off"}, {"integer_datetimes", "on"}, {"TimeZone", "Etc/UTC"}, {"IntervalStyle", "postgres"},
		{"is_superuser", "off"}, {"application_name", st.Params["application_name"]}, {"default_transaction_read_only", "off"},
		{"scram_iterations", "4096"}, {"DateStyle", "ISO, MDY"}, {"standard_conforming_strings", "on"},
		{"session_authorization", user}, {"client_encoding", "UTF8"}, {"server_version", s.version() + " (Debian " + s.version() + "-1.pgdg120+1)"},
		{"server_encoding", "UTF8"},
	} {
		buf.Write(ParameterStatus(kv[0], kv[1]))
	}
	var key [4]byte
	_, _ = rand.Read(key[:])
	buf.Write(BackendKeyData(s.pid.Add(1)+4000, binary.BigEndian.Uint32(key[:])))
	buf.Write(ReadyForQuery('I'))
	if _, err := c.Write(buf.Bytes()); err != nil {
		return
	}
	s.queryLoop(ctx, c, fakedb.Env{User: user, Database: db, RemoteIP: c.Rec.RemoteIP, Version: s.version()})
}

type portal struct {
	stmt string
	res  fakedb.Result
}

func (s *Server) queryLoop(ctx context.Context, c *hpcore.Session, env fakedb.Env) {
	stmts := map[string]string{} // prepared statements by name
	portals := map[string]portal{}
	inError := false // extended protocol: skip until Sync after an error
	for ctx.Err() == nil {
		m, err := ReadMessage(c, c.Limits.MaxPacket)
		if err != nil {
			return
		}
		if inError && m.Type != 'S' && m.Type != 'X' {
			continue
		}
		switch m.Type {
		case 'X': // Terminate
			c.Event("terminate", nil)
			return
		case 'Q':
			sql, _ := parseCString(m.Body)
			if !c.Query(sql) {
				_, _ = c.Write(ErrorResponse("53300", "too many connections for role"))
				return
			}
			var out bytes.Buffer
			// Simple protocol may carry several statements separated by ';'.
			for _, stmt := range splitStatements(sql) {
				res := fakedb.Answer(fakedb.Postgres, stmt, env)
				writeResult(&out, res, true)
				if res.Err != nil {
					break
				}
			}
			out.Write(ReadyForQuery('I'))
			if _, err := c.Write(out.Bytes()); err != nil {
				return
			}
		case 'P': // Parse: name, query, nparams...
			name, rest := parseCString(m.Body)
			sql, _ := parseCString(rest)
			if !c.Query(sql) {
				_, _ = c.Write(ErrorResponse("53300", "too many connections for role"))
				return
			}
			if len(stmts) > 64 {
				stmts = map[string]string{}
			}
			stmts[name] = sql
			if _, err := c.Write(ParseComplete); err != nil {
				return
			}
		case 'B': // Bind: portal, statement, ... (parameters ignored)
			pname, rest := parseCString(m.Body)
			sname, _ := parseCString(rest)
			sql, ok := stmts[sname]
			if !ok {
				inError = true
				if _, err := c.Write(ErrorResponse("26000", fmt.Sprintf("prepared statement \"%s\" does not exist", sname))); err != nil {
					return
				}
				continue
			}
			if len(portals) > 64 {
				portals = map[string]portal{}
			}
			portals[pname] = portal{stmt: sql, res: fakedb.Answer(fakedb.Postgres, sql, env)}
			if _, err := c.Write(BindComplete); err != nil {
				return
			}
		case 'D': // Describe: 'S' statement or 'P' portal
			if len(m.Body) < 1 {
				continue
			}
			name, _ := parseCString(m.Body[1:])
			var res fakedb.Result
			var out bytes.Buffer
			if m.Body[0] == 'S' {
				sql, ok := stmts[name]
				if !ok {
					inError = true
					if _, err := c.Write(ErrorResponse("26000", fmt.Sprintf("prepared statement \"%s\" does not exist", name))); err != nil {
						return
					}
					continue
				}
				res = fakedb.Answer(fakedb.Postgres, sql, env)
				out.Write(ParamDescNone)
			} else {
				p, ok := portals[name]
				if !ok {
					inError = true
					if _, err := c.Write(ErrorResponse("34000", fmt.Sprintf("portal \"%s\" does not exist", name))); err != nil {
						return
					}
					continue
				}
				res = p.res
			}
			if res.Err != nil {
				inError = true
				out.Write(ErrorResponse(res.Err.SQLState, res.Err.Message))
			} else if len(res.Cols) == 0 {
				out.Write(NoData)
			} else {
				out.Write(RowDescription(res.Cols))
			}
			if _, err := c.Write(out.Bytes()); err != nil {
				return
			}
		case 'E': // Execute: portal, max rows
			name, _ := parseCString(m.Body)
			p, ok := portals[name]
			if !ok {
				inError = true
				if _, err := c.Write(ErrorResponse("34000", fmt.Sprintf("portal \"%s\" does not exist", name))); err != nil {
					return
				}
				continue
			}
			var out bytes.Buffer
			writeResult(&out, p.res, false)
			if p.res.Err != nil {
				inError = true
			}
			if _, err := c.Write(out.Bytes()); err != nil {
				return
			}
		case 'C': // Close
			if _, err := c.Write(CloseComplete); err != nil {
				return
			}
		case 'S': // Sync
			inError = false
			if _, err := c.Write(ReadyForQuery('I')); err != nil {
				return
			}
		case 'H': // Flush: nothing buffered
		case 'd', 'c', 'f': // COPY data/done/fail: not in COPY mode
			inError = true
			_, _ = c.Write(ErrorResponse("08P01", "unexpected message type "+string(m.Type)))
		case 'F': // Function call
			c.Event("function_call", map[string]any{"raw": fmt.Sprintf("%x", truncate(m.Body, 128))})
			_, _ = c.Write(ErrorResponse("42883", "function with OID does not exist"))
			_, _ = c.Write(ReadyForQuery('I'))
		default:
			c.Event("message", map[string]any{"type": string(m.Type), "raw": fmt.Sprintf("%x", truncate(m.Body, 128))})
			_, _ = c.Write(ErrorResponse("08P01", "invalid frontend message type "+fmt.Sprintf("%d", m.Type)))
			return
		}
	}
}

func truncate(b []byte, n int) []byte {
	if len(b) > n {
		return b[:n]
	}
	return b
}

// writeResult appends the backend messages for res. withDesc adds the
// RowDescription (simple protocol); Execute in the extended protocol omits it.
func writeResult(out *bytes.Buffer, res fakedb.Result, withDesc bool) {
	if res.Err != nil {
		out.Write(ErrorResponse(res.Err.SQLState, res.Err.Message))
		return
	}
	if res.Tag == "EMPTY" {
		out.Write(EmptyQuery)
		return
	}
	if len(res.Cols) == 0 {
		tag := res.Tag
		if tag == "" {
			tag = "SELECT 0"
		}
		out.Write(CommandComplete(tag))
		return
	}
	if withDesc {
		out.Write(RowDescription(res.Cols))
	}
	for _, r := range res.Rows {
		out.Write(DataRow(r))
	}
	out.Write(CommandComplete(fmt.Sprintf("SELECT %d", len(res.Rows))))
}

// splitStatements splits on ';' outside quotes (good enough for probes).
func splitStatements(sql string) []string {
	var out []string
	var cur strings.Builder
	var quote byte
	for i := 0; i < len(sql); i++ {
		ch := sql[i]
		switch {
		case quote != 0:
			if ch == quote {
				quote = 0
			}
			cur.WriteByte(ch)
		case ch == '\'' || ch == '"':
			quote = ch
			cur.WriteByte(ch)
		case ch == ';':
			if strings.TrimSpace(cur.String()) != "" {
				out = append(out, cur.String())
			}
			cur.Reset()
		default:
			cur.WriteByte(ch)
		}
	}
	if strings.TrimSpace(cur.String()) != "" {
		out = append(out, cur.String())
	}
	if len(out) == 0 {
		out = []string{""}
	}
	return out
}
