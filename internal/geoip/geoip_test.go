package geoip

import (
	"strings"
	"testing"
)

const sample = `1.0.0.0	1.0.0.255	13335	US	CLOUDFLARENET
1.0.1.0	1.0.3.255	0	None	Not routed
8.8.8.0	8.8.8.255	15169	US	GOOGLE
45.9.148.0	45.9.148.255	204957	RU	SOME-RU-NET
2001:4860::	2001:4860:ffff:ffff:ffff:ffff:ffff:ffff	15169	US	GOOGLE
`

func load(t *testing.T) *DB {
	t.Helper()
	db, err := parse(strings.NewReader(sample))
	if err != nil {
		t.Fatal(err)
	}
	return db
}

func TestLookupV4(t *testing.T) {
	db := load(t)
	if db.Len() != 4 { // the AS0/None row is dropped
		t.Fatalf("len = %d, want 4", db.Len())
	}
	for _, tc := range []struct {
		ip, country string
		asn         uint32
		ok          bool
	}{
		{"8.8.8.8", "US", 15169, true},
		{"1.0.0.1", "US", 13335, true},
		{"45.9.148.200", "RU", 204957, true},
		{"1.0.2.1", "", 0, false}, // inside the dropped range: unattributed
		{"9.9.9.9", "", 0, false}, // between ranges
		{"0.0.0.1", "", 0, false}, // before the first range
		{"not-an-ip", "", 0, false},
	} {
		rec, ok := db.Lookup(tc.ip)
		if ok != tc.ok || rec.Country != tc.country || rec.ASN != tc.asn {
			t.Errorf("Lookup(%s) = %+v,%v; want asn=%d country=%q ok=%v", tc.ip, rec, ok, tc.asn, tc.country, tc.ok)
		}
	}
}

func TestLookupV6(t *testing.T) {
	db := load(t)
	rec, ok := db.Lookup("2001:4860:4860::8888")
	if !ok || rec.ASN != 15169 || rec.Country != "US" {
		t.Errorf("v6 lookup = %+v,%v", rec, ok)
	}
	if _, ok := db.Lookup("2606:4700::1"); ok {
		t.Error("unexpected v6 hit outside any range")
	}
}

func TestNilAndEmpty(t *testing.T) {
	var db *DB
	if _, ok := db.Lookup("8.8.8.8"); ok || db.Len() != 0 {
		t.Error("nil DB should resolve nothing")
	}
	empty, _ := parse(strings.NewReader(""))
	if _, ok := empty.Lookup("8.8.8.8"); ok {
		t.Error("empty DB should resolve nothing")
	}
}
