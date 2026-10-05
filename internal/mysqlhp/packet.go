// Package mysqlhp implements enough of the MySQL client/server protocol
// (handshake v10, mysql_native_password, text result sets) to look like a
// MySQL 8 server to clients and scanners.
package mysqlhp

import (
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Capability flags (subset).
const (
	capLongPassword               = 0x00000001
	capFoundRows                  = 0x00000002
	capLongFlag                   = 0x00000004
	capConnectWithDB              = 0x00000008
	capNoSchema                   = 0x00000010
	capCompress                   = 0x00000020
	capODBC                       = 0x00000040
	capLocalFiles                 = 0x00000080
	capIgnoreSpace                = 0x00000100
	capProtocol41                 = 0x00000200
	capInteractive                = 0x00000400
	capSSL                        = 0x00000800
	capTransactions               = 0x00002000
	capSecureConnection           = 0x00008000
	capMultiStatements            = 0x00010000
	capMultiResults               = 0x00020000
	capPSMultiResults             = 0x00040000
	capPluginAuth                 = 0x00080000
	capConnectAttrs               = 0x00100000
	capPluginAuthLenencClientData = 0x00200000
	capDeprecateEOF               = 0x01000000
)

// ServerCapabilities is what the greeting advertises. No SSL, no DEPRECATE_EOF
// (classic EOF-terminated result sets are the most widely understood).
const ServerCapabilities uint32 = capLongPassword | capFoundRows | capLongFlag | capConnectWithDB |
	capNoSchema | capODBC | capIgnoreSpace | capProtocol41 | capInteractive | capTransactions |
	capSecureConnection | capMultiStatements | capMultiResults | capPSMultiResults | capPluginAuth |
	capConnectAttrs | capPluginAuthLenencClientData

// Commands.
const (
	comQuit        = 0x01
	comInitDB      = 0x02
	comQuery       = 0x03
	comFieldList   = 0x04
	comStatistics  = 0x09
	comPing        = 0x0e
	comStmtPrepare = 0x16
	comStmtClose   = 0x19
	comResetConn   = 0x1f
)

const statusAutocommit = 0x0002

// MaxPacket is the largest payload we accept from a client (1 MiB).
const MaxPacket = 1 << 20

var errPacketTooLarge = errors.New("mysql: packet too large")

// ReadPacket reads one framed packet (3-byte length, 1-byte sequence).
func ReadPacket(r io.Reader, maxLen int) (seq byte, payload []byte, err error) {
	var hdr [4]byte
	if _, err = io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, err
	}
	n := int(hdr[0]) | int(hdr[1])<<8 | int(hdr[2])<<16
	if n > maxLen || n == 0xffffff {
		return hdr[3], nil, errPacketTooLarge
	}
	payload = make([]byte, n)
	_, err = io.ReadFull(r, payload)
	return hdr[3], payload, err
}

// WritePacket frames payload with the given sequence id.
func WritePacket(w io.Writer, seq byte, payload []byte) error {
	buf := make([]byte, 4+len(payload))
	buf[0] = byte(len(payload))
	buf[1] = byte(len(payload) >> 8)
	buf[2] = byte(len(payload) >> 16)
	buf[3] = seq
	copy(buf[4:], payload)
	_, err := w.Write(buf)
	return err
}

// Handshake is the server greeting (protocol v10).
type Handshake struct {
	ServerVersion string
	ConnectionID  uint32
	Salt          [20]byte
	Capabilities  uint32
	CharSet       byte
	Status        uint16
	AuthPlugin    string
}

// Encode renders the greeting payload.
func (h Handshake) Encode() []byte {
	b := []byte{10}
	b = append(b, h.ServerVersion...)
	b = append(b, 0)
	b = binary.LittleEndian.AppendUint32(b, h.ConnectionID)
	b = append(b, h.Salt[:8]...)
	b = append(b, 0)
	b = binary.LittleEndian.AppendUint16(b, uint16(h.Capabilities))
	b = append(b, h.CharSet)
	b = binary.LittleEndian.AppendUint16(b, h.Status)
	b = binary.LittleEndian.AppendUint16(b, uint16(h.Capabilities>>16))
	if h.Capabilities&capPluginAuth != 0 {
		b = append(b, 21) // auth plugin data length (20 + NUL)
	} else {
		b = append(b, 0)
	}
	b = append(b, make([]byte, 10)...)
	if h.Capabilities&capSecureConnection != 0 {
		b = append(b, h.Salt[8:20]...)
		b = append(b, 0)
	}
	if h.Capabilities&capPluginAuth != 0 {
		b = append(b, h.AuthPlugin...)
		b = append(b, 0)
	}
	return b
}

// HandshakeResponse is what the client sends back (HandshakeResponse41 or
// the old 320 variant, or an SSLRequest).
type HandshakeResponse struct {
	Capabilities  uint32
	MaxPacketSize uint32
	CharSet       byte
	Username      string
	AuthResponse  []byte
	Database      string
	AuthPlugin    string
	Attrs         map[string]string
	SSLRequest    bool
	Protocol41    bool
}

// DecodeHandshakeResponse parses the client's reply.
func DecodeHandshakeResponse(p []byte) (*HandshakeResponse, error) {
	r := &HandshakeResponse{}
	if len(p) < 2 {
		return nil, errors.New("mysql: handshake response too short")
	}
	if binary.LittleEndian.Uint16(p)&capProtocol41 == 0 {
		// HandshakeResponse320: cap(2) maxpacket(3) user NUL [auth NUL [db]]
		if len(p) < 5 {
			return nil, errors.New("mysql: short 320 response")
		}
		r.Capabilities = uint32(binary.LittleEndian.Uint16(p))
		r.MaxPacketSize = uint32(p[2]) | uint32(p[3])<<8 | uint32(p[4])<<16
		rest := p[5:]
		var ok bool
		r.Username, rest, ok = cutNul(rest)
		if !ok {
			return nil, errors.New("mysql: 320 response without username terminator")
		}
		if r.Capabilities&capConnectWithDB != 0 {
			var auth string
			auth, rest, _ = cutNul(rest)
			r.AuthResponse = []byte(auth)
			r.Database, _, _ = cutNul(rest)
		} else {
			r.AuthResponse = rest
		}
		r.AuthPlugin = "mysql_old_password"
		return r, nil
	}
	if len(p) < 32 {
		return nil, errors.New("mysql: short 41 response")
	}
	r.Protocol41 = true
	r.Capabilities = binary.LittleEndian.Uint32(p)
	r.MaxPacketSize = binary.LittleEndian.Uint32(p[4:])
	r.CharSet = p[8]
	if len(p) == 32 {
		r.SSLRequest = r.Capabilities&capSSL != 0
		return r, nil
	}
	rest := p[32:]
	var ok bool
	r.Username, rest, ok = cutNul(rest)
	if !ok {
		return nil, errors.New("mysql: response without username terminator")
	}
	switch {
	case r.Capabilities&capPluginAuthLenencClientData != 0:
		n, l, lerr := readLenenc(rest)
		if lerr != nil || int(n) > len(rest)-l {
			return nil, errors.New("mysql: bad lenenc auth response")
		}
		r.AuthResponse = rest[l : l+int(n)]
		rest = rest[l+int(n):]
	case r.Capabilities&capSecureConnection != 0:
		if len(rest) < 1 || int(rest[0]) > len(rest)-1 {
			return nil, errors.New("mysql: bad auth response length")
		}
		n := int(rest[0])
		r.AuthResponse = rest[1 : 1+n]
		rest = rest[1+n:]
	default:
		var auth string
		auth, rest, _ = cutNul(rest)
		r.AuthResponse = []byte(auth)
	}
	if r.Capabilities&capConnectWithDB != 0 {
		r.Database, rest, _ = cutNul(rest)
	}
	if r.Capabilities&capPluginAuth != 0 {
		r.AuthPlugin, rest, _ = cutNul(rest)
	}
	if r.Capabilities&capConnectAttrs != 0 && len(rest) > 0 {
		total, l, lerr := readLenenc(rest)
		if lerr == nil {
			rest = rest[l:]
			if int(total) < len(rest) {
				rest = rest[:total]
			}
			r.Attrs = map[string]string{}
			for len(rest) > 0 && len(r.Attrs) < 64 {
				k, kr, kerr := readLenencString(rest)
				if kerr != nil {
					break
				}
				v, vr, verr := readLenencString(kr)
				if verr != nil {
					break
				}
				r.Attrs[k] = v
				rest = vr
			}
		}
	}
	return r, nil
}

func cutNul(b []byte) (string, []byte, bool) {
	for i, c := range b {
		if c == 0 {
			return string(b[:i]), b[i+1:], true
		}
	}
	return string(b), nil, false
}

func readLenenc(b []byte) (uint64, int, error) {
	if len(b) == 0 {
		return 0, 0, io.ErrUnexpectedEOF
	}
	switch {
	case b[0] < 0xfb:
		return uint64(b[0]), 1, nil
	case b[0] == 0xfc && len(b) >= 3:
		return uint64(binary.LittleEndian.Uint16(b[1:])), 3, nil
	case b[0] == 0xfd && len(b) >= 4:
		return uint64(b[1]) | uint64(b[2])<<8 | uint64(b[3])<<16, 4, nil
	case b[0] == 0xfe && len(b) >= 9:
		return binary.LittleEndian.Uint64(b[1:]), 9, nil
	}
	return 0, 0, errors.New("mysql: bad lenenc int")
}

func readLenencString(b []byte) (string, []byte, error) {
	n, l, err := readLenenc(b)
	if err != nil {
		return "", nil, err
	}
	if int(n) > len(b)-l {
		return "", nil, io.ErrUnexpectedEOF
	}
	return string(b[l : l+int(n)]), b[l+int(n):], nil
}

func appendLenenc(b []byte, n uint64) []byte {
	switch {
	case n < 0xfb:
		return append(b, byte(n))
	case n < 1<<16:
		return append(b, 0xfc, byte(n), byte(n>>8))
	case n < 1<<24:
		return append(b, 0xfd, byte(n), byte(n>>8), byte(n>>16))
	}
	return binary.LittleEndian.AppendUint64(append(b, 0xfe), n)
}

func appendLenencString(b []byte, s string) []byte {
	b = appendLenenc(b, uint64(len(s)))
	return append(b, s...)
}

// OKPacket renders an OK with autocommit status.
func OKPacket(affected uint64, info string) []byte {
	b := []byte{0x00}
	b = appendLenenc(b, affected)
	b = appendLenenc(b, 0)
	b = binary.LittleEndian.AppendUint16(b, statusAutocommit)
	b = binary.LittleEndian.AppendUint16(b, 0)
	return append(b, info...)
}

// ErrPacket renders an ERR packet with a 5-char SQLSTATE.
func ErrPacket(code uint16, sqlState, msg string) []byte {
	if len(sqlState) != 5 {
		sqlState = "HY000"
	}
	b := []byte{0xff}
	b = binary.LittleEndian.AppendUint16(b, code)
	b = append(b, '#')
	b = append(b, sqlState...)
	return append(b, msg...)
}

// EOFPacket renders the classic 5-byte EOF.
func EOFPacket() []byte {
	b := []byte{0xfe}
	b = binary.LittleEndian.AppendUint16(b, 0)
	return binary.LittleEndian.AppendUint16(b, statusAutocommit)
}

// AuthSwitchRequest asks the client to redo auth with mysql_native_password.
func AuthSwitchRequest(salt [20]byte) []byte {
	b := []byte{0xfe}
	b = append(b, "mysql_native_password"...)
	b = append(b, 0)
	b = append(b, salt[:]...)
	return append(b, 0)
}

// ColumnDef renders a Protocol::ColumnDefinition41 for a VAR_STRING column.
func ColumnDef(name string) []byte {
	b := appendLenencString(nil, "def")
	b = appendLenencString(b, "")   // schema
	b = appendLenencString(b, "")   // table
	b = appendLenencString(b, "")   // org_table
	b = appendLenencString(b, name) // name
	b = appendLenencString(b, name) // org_name
	b = append(b, 0x0c)
	b = binary.LittleEndian.AppendUint16(b, 0x2d) // utf8mb4_general_ci
	b = binary.LittleEndian.AppendUint32(b, 1024) // column length
	b = append(b, 0xfd)                           // MYSQL_TYPE_VAR_STRING
	b = binary.LittleEndian.AppendUint16(b, 0)    // flags
	b = append(b, 0x1f)                           // decimals
	return append(b, 0, 0)
}

// RowPacket renders one text-protocol row; nil = NULL.
func RowPacket(vals []*string) []byte {
	var b []byte
	for _, v := range vals {
		if v == nil {
			b = append(b, 0xfb)
		} else {
			b = appendLenencString(b, *v)
		}
	}
	return b
}

// NativePasswordScramble computes SHA1(pwd) XOR SHA1(salt + SHA1(SHA1(pwd))).
func NativePasswordScramble(password string, salt [20]byte) []byte {
	if password == "" {
		return nil
	}
	h1 := sha1.Sum([]byte(password))
	h2 := sha1.Sum(h1[:])
	h := sha1.New()
	h.Write(salt[:])
	h.Write(h2[:])
	h3 := h.Sum(nil)
	out := make([]byte, 20)
	for i := range out {
		out[i] = h1[i] ^ h3[i]
	}
	return out
}

// CapabilityNames lists set flags for recording.
func CapabilityNames(c uint32) []string {
	names := []struct {
		f uint32
		n string
	}{
		{capLongPassword, "LONG_PASSWORD"}, {capFoundRows, "FOUND_ROWS"}, {capLongFlag, "LONG_FLAG"},
		{capConnectWithDB, "CONNECT_WITH_DB"}, {capNoSchema, "NO_SCHEMA"}, {capCompress, "COMPRESS"},
		{capODBC, "ODBC"}, {capLocalFiles, "LOCAL_FILES"}, {capIgnoreSpace, "IGNORE_SPACE"},
		{capProtocol41, "PROTOCOL_41"}, {capInteractive, "INTERACTIVE"}, {capSSL, "SSL"},
		{capTransactions, "TRANSACTIONS"}, {capSecureConnection, "SECURE_CONNECTION"},
		{capMultiStatements, "MULTI_STATEMENTS"}, {capMultiResults, "MULTI_RESULTS"},
		{capPSMultiResults, "PS_MULTI_RESULTS"}, {capPluginAuth, "PLUGIN_AUTH"},
		{capConnectAttrs, "CONNECT_ATTRS"}, {capPluginAuthLenencClientData, "PLUGIN_AUTH_LENENC_CLIENT_DATA"},
		{capDeprecateEOF, "DEPRECATE_EOF"},
	}
	var out []string
	for _, n := range names {
		if c&n.f != 0 {
			out = append(out, n.n)
		}
	}
	return out
}

func hexBytes(b []byte) string { return fmt.Sprintf("%x", b) }
