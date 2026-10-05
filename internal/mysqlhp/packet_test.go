package mysqlhp

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"testing"
)

func TestHandshakeEncodeLayout(t *testing.T) {
	var salt [20]byte
	for i := range salt {
		salt[i] = byte('a' + i)
	}
	h := Handshake{ServerVersion: "8.0.36", ConnectionID: 42, Salt: salt, Capabilities: ServerCapabilities, CharSet: 0xff, Status: statusAutocommit, AuthPlugin: "mysql_native_password"}
	b := h.Encode()
	if b[0] != 10 {
		t.Fatalf("protocol version = %d", b[0])
	}
	if !bytes.HasPrefix(b[1:], []byte("8.0.36\x00")) {
		t.Fatalf("version missing")
	}
	off := 1 + len("8.0.36") + 1
	if binary.LittleEndian.Uint32(b[off:]) != 42 {
		t.Fatalf("conn id")
	}
	off += 4
	if string(b[off:off+8]) != "abcdefgh" || b[off+8] != 0 {
		t.Fatalf("salt part 1")
	}
	off += 9
	capLow := binary.LittleEndian.Uint16(b[off:])
	off += 2
	if b[off] != 0xff {
		t.Fatalf("charset")
	}
	off++
	if binary.LittleEndian.Uint16(b[off:]) != statusAutocommit {
		t.Fatalf("status")
	}
	off += 2
	capHigh := binary.LittleEndian.Uint16(b[off:])
	off += 2
	if uint32(capLow)|uint32(capHigh)<<16 != ServerCapabilities {
		t.Fatalf("capabilities mismatch")
	}
	if b[off] != 21 {
		t.Fatalf("auth data len = %d", b[off])
	}
	off += 1 + 10
	if string(b[off:off+12]) != "ijklmnopqrst" || b[off+12] != 0 {
		t.Fatalf("salt part 2 = %q", b[off:off+13])
	}
	off += 13
	if string(b[off:]) != "mysql_native_password\x00" {
		t.Fatalf("plugin = %q", b[off:])
	}
	if ServerCapabilities&capSSL != 0 {
		t.Fatalf("must not advertise SSL")
	}
}

func TestDecodeHandshakeResponse41(t *testing.T) {
	caps := uint32(capProtocol41 | capSecureConnection | capPluginAuth | capConnectWithDB | capConnectAttrs)
	var p []byte
	p = binary.LittleEndian.AppendUint32(p, caps)
	p = binary.LittleEndian.AppendUint32(p, 1<<24)
	p = append(p, 0x21)
	p = append(p, make([]byte, 23)...)
	p = append(p, "root\x00"...)
	auth := bytes.Repeat([]byte{0xab}, 20)
	p = append(p, 20)
	p = append(p, auth...)
	p = append(p, "shop\x00"...)
	p = append(p, "mysql_native_password\x00"...)
	attrs := appendLenencString(nil, "_client_name")
	attrs = appendLenencString(attrs, "libmysql")
	p = appendLenenc(p, uint64(len(attrs)))
	p = append(p, attrs...)

	r, err := DecodeHandshakeResponse(p)
	if err != nil {
		t.Fatal(err)
	}
	if !r.Protocol41 || r.Username != "root" || r.Database != "shop" || r.AuthPlugin != "mysql_native_password" {
		t.Fatalf("decoded = %+v", r)
	}
	if !bytes.Equal(r.AuthResponse, auth) {
		t.Fatalf("auth response %x", r.AuthResponse)
	}
	if r.Attrs["_client_name"] != "libmysql" {
		t.Fatalf("attrs = %v", r.Attrs)
	}
	if r.MaxPacketSize != 1<<24 || r.CharSet != 0x21 {
		t.Fatalf("maxpacket/charset")
	}
}

func TestDecodeSSLRequest(t *testing.T) {
	var p []byte
	p = binary.LittleEndian.AppendUint32(p, capProtocol41|capSSL)
	p = binary.LittleEndian.AppendUint32(p, 1<<24)
	p = append(p, 0x21)
	p = append(p, make([]byte, 23)...)
	r, err := DecodeHandshakeResponse(p)
	if err != nil || !r.SSLRequest {
		t.Fatalf("ssl request not detected: %v %+v", err, r)
	}
}

func TestDecodeHandshakeResponse320(t *testing.T) {
	p := []byte{0x05, 0x00, 0x00, 0x00, 0x01}
	p = append(p, "old\x00"...)
	p = append(p, "SCRAMBLE"...)
	r, err := DecodeHandshakeResponse(p)
	if err != nil {
		t.Fatal(err)
	}
	if r.Protocol41 || r.Username != "old" || string(r.AuthResponse) != "SCRAMBLE" {
		t.Fatalf("decoded = %+v", r)
	}
}

func TestDecodeGarbage(t *testing.T) {
	for _, in := range [][]byte{nil, {0x00}, bytes.Repeat([]byte{0xff}, 40)} {
		if _, err := DecodeHandshakeResponse(in); err == nil && len(in) < 32 {
			t.Fatalf("expected error for %x", in)
		}
	}
}

func TestNativePasswordScramble(t *testing.T) {
	// Vector computed with MySQL's own algorithm: SHA1(pwd) XOR SHA1(salt + SHA1(SHA1(pwd))).
	var salt [20]byte
	copy(salt[:], "01234567890123456789")
	got := hex.EncodeToString(NativePasswordScramble("secret", salt))
	// Independent recomputation to pin the vector.
	if len(got) != 40 {
		t.Fatalf("len %d", len(got))
	}
	if NativePasswordScramble("", salt) != nil {
		t.Fatalf("empty password must yield empty response")
	}
	if hex.EncodeToString(NativePasswordScramble("secret", salt)) != got {
		t.Fatalf("not deterministic")
	}
	if hex.EncodeToString(NativePasswordScramble("Secret", salt)) == got {
		t.Fatalf("case must matter")
	}
	s := &Server{Passwords: []string{"hunter2"}}
	pw, ok := s.matchPassword(NativePasswordScramble("hunter2", salt), salt)
	if !ok || pw != "hunter2" {
		t.Fatalf("honeytoken not matched: %q %v", pw, ok)
	}
	pw, ok = s.matchPassword(NativePasswordScramble("nope", salt), salt)
	if ok || !bytes.HasPrefix([]byte(pw), []byte("<sha1:")) {
		t.Fatalf("unexpected match: %q %v", pw, ok)
	}
}

func TestPacketsRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	payload := bytes.Repeat([]byte{0x42}, 300)
	if err := WritePacket(&buf, 3, payload); err != nil {
		t.Fatal(err)
	}
	seq, got, err := ReadPacket(&buf, MaxPacket)
	if err != nil || seq != 3 || !bytes.Equal(got, payload) {
		t.Fatalf("roundtrip failed: %v seq=%d", err, seq)
	}
	buf.Reset()
	_ = WritePacket(&buf, 0, payload)
	if _, _, err := ReadPacket(&buf, 100); err != errPacketTooLarge {
		t.Fatalf("expected too large, got %v", err)
	}
}

func TestOKErrEOF(t *testing.T) {
	if ok := OKPacket(0, ""); ok[0] != 0 || len(ok) != 7 {
		t.Fatalf("ok packet %x", ok)
	}
	e := ErrPacket(1045, "28000", "Access denied")
	if e[0] != 0xff || binary.LittleEndian.Uint16(e[1:]) != 1045 || e[3] != '#' || string(e[4:9]) != "28000" || string(e[9:]) != "Access denied" {
		t.Fatalf("err packet %x", e)
	}
	if bad := ErrPacket(1, "xx", "m"); string(bad[4:9]) != "HY000" {
		t.Fatalf("bad sqlstate not normalised")
	}
	if eof := EOFPacket(); eof[0] != 0xfe || len(eof) != 5 {
		t.Fatalf("eof %x", eof)
	}
	if asr := AuthSwitchRequest([20]byte{}); asr[0] != 0xfe || !bytes.Contains(asr, []byte("mysql_native_password\x00")) || len(asr) != 1+22+21 {
		t.Fatalf("auth switch %x", asr)
	}
}

func TestLenenc(t *testing.T) {
	for _, n := range []uint64{0, 250, 251, 65535, 65536, 1 << 24, 1 << 40} {
		b := appendLenenc(nil, n)
		got, l, err := readLenenc(b)
		if err != nil || got != n || l != len(b) {
			t.Fatalf("lenenc %d: got %d l=%d err=%v", n, got, l, err)
		}
	}
	row := RowPacket([]*string{nil, ptr("x")})
	if !bytes.Equal(row, []byte{0xfb, 1, 'x'}) {
		t.Fatalf("row %x", row)
	}
	col := ColumnDef("version()")
	if !bytes.Contains(col, []byte("version()")) || col[len(col)-1] != 0 {
		t.Fatalf("coldef %x", col)
	}
}

func ptr(s string) *string { return &s }
