package pghp

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func startupBytes(proto uint32, kv ...string) []byte {
	var body []byte
	for i := 0; i+1 < len(kv); i += 2 {
		body = append(body, cstr(kv[i])...)
		body = append(body, cstr(kv[i+1])...)
	}
	if len(kv) > 0 {
		body = append(body, 0)
	}
	out := binary.BigEndian.AppendUint32(nil, uint32(8+len(body)))
	out = binary.BigEndian.AppendUint32(out, proto)
	return append(out, body...)
}

func TestReadStartupV3(t *testing.T) {
	st, err := ReadStartup(bytes.NewReader(startupBytes(protoV3, "user", "postgres", "database", "prod", "application_name", "psql")))
	if err != nil {
		t.Fatal(err)
	}
	if st.Protocol != protoV3 || st.Params["user"] != "postgres" || st.Params["database"] != "prod" || st.Params["application_name"] != "psql" {
		t.Fatalf("startup = %+v", st)
	}
}

func TestReadStartupSSLRequest(t *testing.T) {
	st, err := ReadStartup(bytes.NewReader(startupBytes(sslRequestCode)))
	if err != nil || st.Protocol != sslRequestCode {
		t.Fatalf("ssl request: %v %+v", err, st)
	}
	if _, err := ReadStartup(bytes.NewReader(binary.BigEndian.AppendUint32(nil, 1<<30))); err == nil {
		t.Fatalf("expected error on absurd length")
	}
	if _, err := ReadStartup(bytes.NewReader([]byte{0, 0, 0, 4, 0, 0, 0, 0})); err == nil {
		t.Fatalf("expected error on length < 8")
	}
}

func TestReadMessage(t *testing.T) {
	m, err := ReadMessage(bytes.NewReader(Encode('Q', cstr("select 1"))), 1<<20)
	if err != nil || m.Type != 'Q' || string(m.Body) != "select 1\x00" {
		t.Fatalf("message: %v %+v", err, m)
	}
	if _, err := ReadMessage(bytes.NewReader(Encode('Q', make([]byte, 100))), 10); err == nil {
		t.Fatalf("expected too large")
	}
}

func TestBackendMessages(t *testing.T) {
	if a := AuthCleartext(); !bytes.Equal(a, []byte{'R', 0, 0, 0, 8, 0, 0, 0, 3}) {
		t.Fatalf("cleartext %x", a)
	}
	if a := AuthMD5([4]byte{1, 2, 3, 4}); !bytes.Equal(a, []byte{'R', 0, 0, 0, 12, 0, 0, 0, 5, 1, 2, 3, 4}) {
		t.Fatalf("md5 %x", a)
	}
	if a := AuthOK(); !bytes.Equal(a, []byte{'R', 0, 0, 0, 8, 0, 0, 0, 0}) {
		t.Fatalf("authok %x", a)
	}
	if z := ReadyForQuery('I'); !bytes.Equal(z, []byte{'Z', 0, 0, 0, 5, 'I'}) {
		t.Fatalf("rfq %x", z)
	}
	e := ErrorResponse("42P01", "relation \"x\" does not exist")
	if e[0] != 'E' || !bytes.Contains(e, []byte("C42P01\x00")) || !bytes.Contains(e, []byte("Mrelation \"x\" does not exist\x00")) || e[len(e)-1] != 0 {
		t.Fatalf("error response %q", e)
	}
	rd := RowDescription([]string{"a", "bb"})
	if rd[0] != 'T' || binary.BigEndian.Uint16(rd[5:]) != 2 || int(binary.BigEndian.Uint32(rd[1:])) != len(rd)-1 {
		t.Fatalf("row description %x", rd)
	}
	// per column: name+NUL, 4+2+4+2+4+2 = 18 bytes
	if len(rd) != 5+2+(2+18)+(3+18) {
		t.Fatalf("row description length %d", len(rd))
	}
	v := "x"
	dr := DataRow([]*string{&v, nil})
	want := []byte{'D', 0, 0, 0, 4 + 2 + 4 + 1 + 4, 0, 2, 0, 0, 0, 1, 'x', 0xff, 0xff, 0xff, 0xff}
	if !bytes.Equal(dr, want) {
		t.Fatalf("data row %x want %x", dr, want)
	}
	if c := CommandComplete("SELECT 1"); c[0] != 'C' || string(c[5:]) != "SELECT 1\x00" {
		t.Fatalf("command complete %q", c)
	}
}

func TestMD5Password(t *testing.T) {
	// libpq: "md5" + md5(md5(password + user) + salt). Vector checked against PostgreSQL docs example shape.
	got := MD5Password("secret", "postgres", [4]byte{0x01, 0x02, 0x03, 0x04})
	if len(got) != 35 || got[:3] != "md5" {
		t.Fatalf("md5 shape %q", got)
	}
	if MD5Password("secret", "postgres", [4]byte{9, 9, 9, 9}) == got {
		t.Fatalf("salt must change the hash")
	}
}

func TestSplitStatements(t *testing.T) {
	got := splitStatements("select 1; select 'a;b' ; ")
	if len(got) != 2 || got[1] != " select 'a;b' " {
		t.Fatalf("split = %q", got)
	}
	if got := splitStatements(""); len(got) != 1 {
		t.Fatalf("empty must yield one empty statement: %q", got)
	}
}
