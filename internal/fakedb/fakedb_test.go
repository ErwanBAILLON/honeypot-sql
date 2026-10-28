package fakedb

import "testing"

func TestAnswers(t *testing.T) {
	env := Env{User: "root", Database: "shop", RemoteIP: "203.0.113.9", Version: "8.0.36"}
	cases := []struct {
		d       Dialect
		sql     string
		wantCol string
		wantVal string
		wantErr string
		wantTag string
	}{
		{MySQL, "SELECT VERSION()", "version()", "8.0.36", "", ""},
		{MySQL, "/* mysql-connector */ select @@version_comment limit 1", "@@version_comment", "MySQL Community Server - GPL", "", ""},
		{MySQL, "SHOW DATABASES", "Database", "information_schema", "", ""},
		{MySQL, "select 1", "1", "1", "", ""},
		{MySQL, "SET NAMES utf8mb4", "", "", "", "SET"},
		{MySQL, "select * from users", "", "", "42S02", ""},
		{MySQL, "drop database shop", "", "", "42000", ""},
		{MySQL, "hello world", "", "", "42000", ""},
		{MySQL, "select user()", "user()", "root@203.0.113.9", "", ""},
		{Postgres, "select version()", "version", "PostgreSQL 8.0.36 on x86_64-pc-linux-gnu, compiled by gcc (Debian 12.2.0-14) 12.2.0, 64-bit", "", ""},
		{Postgres, "SELECT d.datname as \"Name\" FROM pg_catalog.pg_database d ORDER BY 1;", "Name", "postgres", "", ""},
		{Postgres, "select table_name from information_schema.tables", "table_catalog", "shop", "", ""},
		{Postgres, "select current_database()", "current_database", "shop", "", ""},
		{Postgres, "begin", "", "", "", "BEGIN"},
		{Postgres, "select * from secrets", "", "", "42P01", ""},
		{Postgres, "garbage;", "", "", "42601", ""},
		{Postgres, "", "", "", "", "EMPTY"},
	}
	for _, c := range cases {
		r := Answer(c.d, c.sql, env)
		if c.wantErr != "" {
			if r.Err == nil || r.Err.SQLState != c.wantErr {
				t.Errorf("%s %q: want error %s, got %+v", c.d, c.sql, c.wantErr, r.Err)
			}
			continue
		}
		if r.Err != nil {
			t.Errorf("%s %q: unexpected error %+v", c.d, c.sql, r.Err)
			continue
		}
		if c.wantTag != "" {
			if r.Tag != c.wantTag {
				t.Errorf("%s %q: tag %q want %q", c.d, c.sql, r.Tag, c.wantTag)
			}
			continue
		}
		if len(r.Cols) == 0 || r.Cols[0] != c.wantCol {
			t.Errorf("%s %q: cols %v want first %q", c.d, c.sql, r.Cols, c.wantCol)
			continue
		}
		if len(r.Rows) == 0 || r.Rows[0][0] == nil || *r.Rows[0][0] != c.wantVal {
			t.Errorf("%s %q: first value = %v want %q", c.d, c.sql, r.Rows, c.wantVal)
		}
	}
}

func TestNormalize(t *testing.T) {
	if got := Normalize("  /* hi */ select   1 ;  "); got != "select 1" {
		t.Fatalf("normalize = %q", got)
	}
}

func TestCanaryPlanting(t *testing.T) {
	minted := map[string]string{}
	env := Env{User: "root", Database: "shop", RemoteIP: "203.0.113.9", Version: "8.0.36",
		Mint: func(kind, label string) string {
			v := kind + ":" + label
			minted[label] = v
			return v
		}}
	for _, d := range []Dialect{MySQL, Postgres} {
		res := Answer(d, "SELECT * FROM users", env)
		if res.Err != nil {
			t.Fatalf("%s: enticing table should be served, got error %+v", d, res.Err)
		}
		if len(res.Rows) != 2 {
			t.Fatalf("%s: want 2 rows, got %d", d, len(res.Rows))
		}
		// The honeytoken credential must be the minted value, placed in the row.
		var found bool
		for _, cell := range res.Rows[1] {
			if cell != nil && *cell == "credential:users.secret" {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: planted credential not found in the row: %v", d, res.Rows[1])
		}
	}
	// Without a Mint, the same query is an ordinary "table does not exist".
	if r := Answer(MySQL, "SELECT * FROM users", Env{Database: "shop"}); r.Err == nil {
		t.Error("canaries off: users should not be served")
	}
}
