// Package geoip attributes a source IP to an autonomous system and a country,
// entirely offline. It reads an ip2asn table (the public-domain TSV published
// at iptoasn.com, plain or gzip): one row per IP range,
//
//	range_start<TAB>range_end<TAB>AS_number<TAB>country_code<TAB>AS_description
//
// Ranges are sorted once and looked up by binary search. No network, no CGO,
// no large embedded database: the file is mounted next to the honeypot, and
// when it is absent the honeypot runs exactly as before (Lookup on a nil *DB
// returns false). This keeps the "never opens outbound connections" invariant.
package geoip

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"net/netip"
	"os"
	"sort"
	"strings"
)

// Record is what a source IP resolves to.
type Record struct {
	ASN     uint32 `json:"asn"`
	Country string `json:"country"` // ISO 3166-1 alpha-2, or "" when unknown
	Org     string `json:"org"`     // AS description
}

type entry struct {
	start, end [16]byte // inclusive, IPv4 held as IPv4-mapped IPv6 so one ordering covers both
	rec        Record
}

// DB is an immutable, sorted set of IP ranges. The zero value and a nil *DB
// are usable: every Lookup returns (Record{}, false).
type DB struct {
	entries []entry
}

// Load reads an ip2asn table from path (gzip when the name ends in .gz).
func Load(path string) (*DB, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var r io.Reader = f
	if strings.HasSuffix(path, ".gz") {
		gz, err := gzip.NewReader(f)
		if err != nil {
			return nil, fmt.Errorf("gzip %s: %w", path, err)
		}
		defer gz.Close()
		r = gz
	}
	return parse(r)
}

func parse(r io.Reader) (*DB, error) {
	db := &DB{}
	intern := map[string]string{} // AS descriptions repeat across thousands of ranges
	keep := func(s string) string {
		if v, ok := intern[s]; ok {
			return v
		}
		intern[s] = s
		return s
	}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) < 5 {
			continue
		}
		lo, err1 := netip.ParseAddr(strings.TrimSpace(f[0]))
		hi, err2 := netip.ParseAddr(strings.TrimSpace(f[1]))
		if err1 != nil || err2 != nil {
			continue
		}
		asn := parseUint(f[2])
		country := strings.TrimSpace(f[3])
		if asn == 0 || country == "" || country == "None" {
			continue // unannounced range: nothing to attribute
		}
		db.entries = append(db.entries, entry{
			start: lo.As16(),
			end:   hi.As16(),
			rec:   Record{ASN: asn, Country: country, Org: keep(strings.TrimSpace(f[4]))},
		})
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	sort.Slice(db.entries, func(i, j int) bool {
		return bytes.Compare(db.entries[i].start[:], db.entries[j].start[:]) < 0
	})
	return db, nil
}

// Len is the number of ranges held.
func (db *DB) Len() int {
	if db == nil {
		return 0
	}
	return len(db.entries)
}

// Lookup resolves an IP string. It reports false for a nil DB, an unparseable
// address, or an address in no known range.
func (db *DB) Lookup(ip string) (Record, bool) {
	if db == nil || len(db.entries) == 0 {
		return Record{}, false
	}
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return Record{}, false
	}
	key := addr.As16()
	// Rightmost entry whose start <= key, then an inclusive end check. Ranges
	// in the ip2asn table do not overlap, so the candidate is unique.
	i := sort.Search(len(db.entries), func(i int) bool {
		return bytes.Compare(db.entries[i].start[:], key[:]) > 0
	})
	if i == 0 {
		return Record{}, false
	}
	e := db.entries[i-1]
	if bytes.Compare(key[:], e.end[:]) <= 0 {
		return e.rec, true
	}
	return Record{}, false
}

func parseUint(s string) uint32 {
	var n uint32
	for _, c := range strings.TrimSpace(s) {
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + uint32(c-'0')
	}
	return n
}
