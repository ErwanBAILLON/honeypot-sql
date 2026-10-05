// Package pghp implements enough of the PostgreSQL frontend/backend protocol
// v3 (startup, SSLRequest refusal, cleartext/md5 password, simple and
// extended query) to look like a PostgreSQL 16 server.
package pghp

import (
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
)

const (
	protoV3          = 196608
	sslRequestCode   = 80877103
	gssEncRequest    = 80877104
	cancelRequest    = 80877102
	maxStartupLength = 10000
)

// Startup is the parsed StartupMessage.
type Startup struct {
	Protocol uint32
	Params   map[string]string // user, database, application_name, client_encoding...
}

// ReadStartup reads one startup-phase message (length-prefixed, no type byte).
func ReadStartup(r io.Reader) (*Startup, error) {
	var hdr [8]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:4])
	if n < 8 || n > maxStartupLength {
		return nil, errors.New("pg: invalid startup length")
	}
	st := &Startup{Protocol: binary.BigEndian.Uint32(hdr[4:]), Params: map[string]string{}}
	body := make([]byte, n-8)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}
	if st.Protocol == protoV3 {
		for len(body) > 0 {
			k, rest, ok := cutNul(body)
			if !ok || k == "" {
				break
			}
			v, rest2, _ := cutNul(rest)
			st.Params[k] = v
			body = rest2
			if len(st.Params) > 64 {
				break
			}
		}
	}
	return st, nil
}

func cutNul(b []byte) (string, []byte, bool) {
	for i, c := range b {
		if c == 0 {
			return string(b[:i]), b[i+1:], true
		}
	}
	return string(b), nil, false
}

// Message is a typed frontend message.
type Message struct {
	Type byte
	Body []byte
}

// ReadMessage reads one typed message.
func ReadMessage(r io.Reader, maxLen int) (*Message, error) {
	var hdr [5]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint32(hdr[1:]))
	if n < 4 || n-4 > maxLen {
		return nil, errors.New("pg: invalid message length")
	}
	m := &Message{Type: hdr[0], Body: make([]byte, n-4)}
	_, err := io.ReadFull(r, m.Body)
	return m, err
}

// Encode frames a backend message.
func Encode(t byte, body []byte) []byte {
	out := make([]byte, 5+len(body))
	out[0] = t
	binary.BigEndian.PutUint32(out[1:], uint32(4+len(body)))
	copy(out[5:], body)
	return out
}

func cstr(s string) []byte { return append([]byte(s), 0) }

// AuthCleartext asks for a cleartext password.
func AuthCleartext() []byte { return Encode('R', binary.BigEndian.AppendUint32(nil, 3)) }

// AuthMD5 asks for an md5 password with salt.
func AuthMD5(salt [4]byte) []byte {
	return Encode('R', append(binary.BigEndian.AppendUint32(nil, 5), salt[:]...))
}

// AuthOK is AuthenticationOk.
func AuthOK() []byte { return Encode('R', binary.BigEndian.AppendUint32(nil, 0)) }

// ParameterStatus reports a server setting.
func ParameterStatus(k, v string) []byte { return Encode('S', append(cstr(k), cstr(v)...)) }

// BackendKeyData gives pid and secret key.
func BackendKeyData(pid, key uint32) []byte {
	return Encode('K', binary.BigEndian.AppendUint32(binary.BigEndian.AppendUint32(nil, pid), key))
}

// ReadyForQuery with transaction status (I, T or E).
func ReadyForQuery(status byte) []byte { return Encode('Z', []byte{status}) }

// ErrorResponse renders an error with the usual fields.
func ErrorResponse(sqlState, msg string) []byte {
	var b []byte
	b = append(b, 'S')
	b = append(b, cstr("ERROR")...)
	b = append(b, 'V')
	b = append(b, cstr("ERROR")...)
	b = append(b, 'C')
	b = append(b, cstr(sqlState)...)
	b = append(b, 'M')
	b = append(b, cstr(msg)...)
	b = append(b, 'F')
	b = append(b, cstr("parse_relation.c")...)
	b = append(b, 'L')
	b = append(b, cstr("1392")...)
	b = append(b, 'R')
	b = append(b, cstr("parserOpenTable")...)
	b = append(b, 0)
	return Encode('E', b)
}

// RowDescription for text columns (oid 25).
func RowDescription(cols []string) []byte {
	b := binary.BigEndian.AppendUint16(nil, uint16(len(cols)))
	for _, c := range cols {
		b = append(b, cstr(c)...)
		b = binary.BigEndian.AppendUint32(b, 0)          // table oid
		b = binary.BigEndian.AppendUint16(b, 0)          // column attr
		b = binary.BigEndian.AppendUint32(b, 25)         // type oid: text
		b = binary.BigEndian.AppendUint16(b, 0xffff)     // typlen -1
		b = binary.BigEndian.AppendUint32(b, 0xffffffff) // typmod -1
		b = binary.BigEndian.AppendUint16(b, 0)          // text format
	}
	return Encode('T', b)
}

// DataRow renders one row; nil = NULL.
func DataRow(vals []*string) []byte {
	b := binary.BigEndian.AppendUint16(nil, uint16(len(vals)))
	for _, v := range vals {
		if v == nil {
			b = binary.BigEndian.AppendUint32(b, 0xffffffff)
			continue
		}
		b = binary.BigEndian.AppendUint32(b, uint32(len(*v)))
		b = append(b, *v...)
	}
	return Encode('D', b)
}

// CommandComplete with a tag such as "SELECT 3".
func CommandComplete(tag string) []byte { return Encode('C', cstr(tag)) }

// Simple one-byte-body-less backend messages.
var (
	ParseComplete = Encode('1', nil)
	BindComplete  = Encode('2', nil)
	CloseComplete = Encode('3', nil)
	NoData        = Encode('n', nil)
	EmptyQuery    = Encode('I', nil)
	ParamDescNone = Encode('t', binary.BigEndian.AppendUint16(nil, 0))
)

// MD5Password computes "md5" + md5(md5(password + user) + salt) as libpq does.
func MD5Password(password, user string, salt [4]byte) string {
	inner := md5.Sum([]byte(password + user))
	h := md5.New()
	h.Write([]byte(hex.EncodeToString(inner[:])))
	h.Write(salt[:])
	return "md5" + hex.EncodeToString(h.Sum(nil))
}

// parseCString reads a NUL-terminated string from body.
func parseCString(b []byte) (string, []byte) {
	s, rest, _ := cutNul(b)
	return s, rest
}
