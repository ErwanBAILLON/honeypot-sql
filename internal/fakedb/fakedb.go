// Package fakedb answers a handful of common SQL statements so that scanners
// and bots keep talking. Nothing is ever executed: every answer is static.
package fakedb

import (
	"regexp"
	"strings"
)

// Dialect selects the flavour of the canned answers.
type Dialect string

const (
	MySQL    Dialect = "mysql"
	Postgres Dialect = "postgres"
)

// Env is what the canned answers may echo back.
type Env struct {
	User, Database, RemoteIP string
	Version                  string // server version string advertised in the handshake
	// Mint, when set, plants a canary token and returns the value to embed in
	// the fake data (kind "credential" or "url", label = planting site). nil
	// leaves the answers free of canaries, as before.
	Mint func(kind, label string) string
}

// plant returns a canary value for (kind, label), or "" when canaries are off.
func (e Env) plant(kind, label string) string {
	if e.Mint == nil {
		return ""
	}
	return e.Mint(kind, label)
}

// enticingTables are fake tables worth serving (with planted tokens) instead of
// "table does not exist", so an attacker who dumps them carries our markers.
var enticingTables = map[string]bool{
	"users": true, "accounts": true, "customers": true, "credentials": true, "creds": true,
	"secrets": true, "api_keys": true, "apikeys": true, "tokens": true, "config": true,
	"configs": true, "settings": true, "passwords": true, "logins": true,
}

// canaryTable builds a small, believable result for a dump of an enticing table,
// carrying one honeytoken credential and one beacon URL. It returns ok=false
// when canaries are off or the table is not one we bait.
func canaryTable(q string, env Env) (Result, bool) {
	if env.Mint == nil {
		return Result{}, false
	}
	t := strings.ToLower(tableName(q))
	if i := strings.LastIndex(t, "."); i >= 0 {
		t = t[i+1:]
	}
	if !enticingTables[t] {
		return Result{}, false
	}
	cred := env.plant("credential", t+".secret")
	url := env.plant("url", t+".backup_url")
	if cred == "" && url == "" {
		return Result{}, false // per-session cap reached: fall back to the normal answer
	}
	secret, backup := cred, url
	if secret == "" {
		secret = "s3cr3t-rotated-2026"
	}
	var backupCell *string
	if backup != "" {
		backupCell = s(backup)
	}
	return Result{
		Cols: []string{"id", "username", "email", "secret", "backup_url"},
		Rows: [][]*string{
			{s("1"), s("admin"), s("admin@corp.internal"), s("$2y$10$9QF1u6kqZwLx3nR2uO7redacted"), nil},
			{s("2"), s("svc_backup"), s("backup@corp.internal"), s(secret), backupCell},
		},
	}, true
}

// SQLError is a realistic protocol error.
type SQLError struct {
	Code     int    // MySQL numeric code
	SQLState string // 5-char SQLSTATE
	Message  string
}

// Result is a tabular answer or a command tag or an error.
type Result struct {
	Cols []string
	Rows [][]*string // nil pointer = SQL NULL
	Tag  string      // PG CommandComplete tag ("SET", "BEGIN"...), "" for SELECT
	Err  *SQLError
}

func s(v string) *string { return &v }

var (
	reSpaces   = regexp.MustCompile(`\s+`)
	reFrom     = regexp.MustCompile(`(?i)\b(?:from|into|update|table|join)\s+` + "`?\"?" + `([a-zA-Z0-9_.]+)`)
	reAtVar    = regexp.MustCompile(`(?i)^select\s+@@(?:global\.|session\.)?([a-z_]+)`)
	reShowVar  = regexp.MustCompile(`(?i)^show\s+(?:global\s+|session\s+)?variables(?:\s+like\s+'([^']*)')?`)
	reShowLike = regexp.MustCompile(`(?i)^show\s+(databases|schemas|tables|processlist|status|grants|engines|plugins|privileges|master status|slave status|binary logs)`)
	reFirst    = regexp.MustCompile(`(?i)^([a-z\\]+)`)
)

// Normalize trims whitespace, comments and a trailing semicolon.
func Normalize(sql string) string {
	q := strings.TrimSpace(sql)
	q = strings.TrimSuffix(q, ";")
	q = strings.TrimSpace(q)
	// Strip /* ... */ comments (mysql clients prefix version comments).
	for {
		i := strings.Index(q, "/*")
		if i < 0 {
			break
		}
		j := strings.Index(q[i:], "*/")
		if j < 0 {
			break
		}
		q = q[:i] + q[i+j+2:]
	}
	return strings.TrimSpace(reSpaces.ReplaceAllString(q, " "))
}

// Answer returns a canned result for sql.
func Answer(d Dialect, sql string, env Env) Result {
	q := Normalize(sql)
	lq := strings.ToLower(q)
	if q == "" {
		if d == Postgres {
			return Result{Tag: "EMPTY"}
		}
		return Result{Err: &SQLError{1065, "42000", "Query was empty"}}
	}
	switch {
	case lq == "select 1" || lq == "select 1 as a" || lq == "select 1;" || lq == "select 1 as result":
		return Result{Cols: []string{"1"}, Rows: [][]*string{{s("1")}}}
	case strings.HasPrefix(lq, "select version()"), strings.HasPrefix(lq, "select @@version "), lq == "select @@version":
		if d == Postgres {
			return Result{Cols: []string{"version"}, Rows: [][]*string{{s("PostgreSQL " + env.Version + " on x86_64-pc-linux-gnu, compiled by gcc (Debian 12.2.0-14) 12.2.0, 64-bit")}}}
		}
		return Result{Cols: []string{"version()"}, Rows: [][]*string{{s(env.Version)}}}
	case strings.HasPrefix(lq, "select user()"), strings.HasPrefix(lq, "select current_user"), strings.HasPrefix(lq, "select session_user"):
		if d == Postgres {
			return Result{Cols: []string{"current_user"}, Rows: [][]*string{{s(orDefault(env.User, "postgres"))}}}
		}
		return Result{Cols: []string{"user()"}, Rows: [][]*string{{s(orDefault(env.User, "root") + "@" + env.RemoteIP)}}}
	case strings.HasPrefix(lq, "select database()"), strings.HasPrefix(lq, "select current_database()"), strings.HasPrefix(lq, "select schema()"):
		var v *string
		if env.Database != "" {
			v = s(env.Database)
		} else if d == Postgres {
			v = s("postgres")
		}
		name := "database()"
		if d == Postgres {
			name = "current_database"
		}
		return Result{Cols: []string{name}, Rows: [][]*string{{v}}}
	case strings.HasPrefix(lq, "select now()"), strings.HasPrefix(lq, "select current_timestamp"):
		return Result{Cols: []string{"now"}, Rows: [][]*string{{s("2026-01-01 00:00:00")}}}
	case strings.HasPrefix(lq, "set "), strings.HasPrefix(lq, "reset "), strings.HasPrefix(lq, "discard "):
		return Result{Tag: "SET"}
	case lq == "begin" || lq == "start transaction" || strings.HasPrefix(lq, "begin "):
		return Result{Tag: "BEGIN"}
	case lq == "commit":
		return Result{Tag: "COMMIT"}
	case lq == "rollback":
		return Result{Tag: "ROLLBACK"}
	case strings.HasPrefix(lq, "use "):
		return Result{Tag: "USE"}
	}
	if d == MySQL {
		return mysqlAnswer(q, lq, env)
	}
	return pgAnswer(q, lq, env)
}

func orDefault(v, d string) string {
	if v == "" {
		return d
	}
	return v
}

func tableName(q string) string {
	if m := reFrom.FindStringSubmatch(q); m != nil {
		return strings.Trim(m[1], "`\"")
	}
	return "unknown"
}

var mysqlVars = map[string]string{
	"version_comment":          "MySQL Community Server - GPL",
	"max_allowed_packet":       "67108864",
	"sql_mode":                 "ONLY_FULL_GROUP_BY,STRICT_TRANS_TABLES,NO_ZERO_IN_DATE,NO_ZERO_DATE,ERROR_FOR_DIVISION_BY_ZERO,NO_ENGINE_SUBSTITUTION",
	"character_set_client":     "utf8mb4",
	"character_set_results":    "utf8mb4",
	"character_set_connection": "utf8mb4",
	"collation_connection":     "utf8mb4_0900_ai_ci",
	"autocommit":               "1",
	"tx_isolation":             "REPEATABLE-READ",
	"transaction_isolation":    "REPEATABLE-READ",
	"wait_timeout":             "28800",
	"interactive_timeout":      "28800",
	"lower_case_table_names":   "0",
	"hostname":                 "db-prod-01",
	"datadir":                  "/var/lib/mysql/",
	"basedir":                  "/usr/",
	"port":                     "3306",
	"have_ssl":                 "DISABLED",
	"secure_file_priv":         "/var/lib/mysql-files/",
	"version_compile_os":       "Linux",
	"version_compile_machine":  "x86_64",
	"system_time_zone":         "UTC",
	"time_zone":                "SYSTEM",
	"net_write_timeout":        "60",
	"net_read_timeout":         "30",
	"sql_auto_is_null":         "0",
	"init_connect":             "",
	"license":                  "GPL",
}

func mysqlAnswer(q, lq string, env Env) Result {
	if m := reAtVar.FindStringSubmatch(q); m != nil {
		name := strings.ToLower(m[1])
		v := mysqlVars[name]
		if name == "version" {
			v = env.Version
		}
		return Result{Cols: []string{"@@" + m[1]}, Rows: [][]*string{{s(v)}}}
	}
	if m := reShowVar.FindStringSubmatch(q); m != nil {
		res := Result{Cols: []string{"Variable_name", "Value"}}
		like := strings.ToLower(strings.ReplaceAll(m[1], "%", ""))
		for k, v := range mysqlVars {
			if like == "" || strings.Contains(k, like) {
				res.Rows = append(res.Rows, []*string{s(k), s(v)})
			}
		}
		if strings.Contains("version", like) {
			res.Rows = append(res.Rows, []*string{s("version"), s(env.Version)})
		}
		return res
	}
	if m := reShowLike.FindStringSubmatch(q); m != nil {
		switch strings.ToLower(m[1]) {
		case "databases", "schemas":
			return Result{Cols: []string{"Database"}, Rows: [][]*string{{s("information_schema")}, {s("mysql")}, {s("performance_schema")}, {s("sys")}}}
		case "tables":
			return Result{Cols: []string{"Tables_in_" + orDefault(env.Database, "mysql")}}
		case "processlist":
			return Result{Cols: []string{"Id", "User", "Host", "db", "Command", "Time", "State", "Info"},
				Rows: [][]*string{{s("12"), s(orDefault(env.User, "root")), s(env.RemoteIP), nil, s("Query"), s("0"), s("init"), s(q)}}}
		case "grants":
			return Result{Cols: []string{"Grants for " + orDefault(env.User, "root") + "@%"}, Rows: [][]*string{{s("GRANT USAGE ON *.* TO `" + orDefault(env.User, "root") + "`@`%`")}}}
		case "engines":
			return Result{Cols: []string{"Engine", "Support", "Comment", "Transactions", "XA", "Savepoints"},
				Rows: [][]*string{{s("InnoDB"), s("DEFAULT"), s("Supports transactions, row-level locking, and foreign keys"), s("YES"), s("YES"), s("YES")}}}
		default:
			return Result{Cols: []string{"Variable_name", "Value"}}
		}
	}
	if strings.Contains(lq, "information_schema.schemata") {
		return Result{Cols: []string{"SCHEMA_NAME"}, Rows: [][]*string{{s("information_schema")}, {s("mysql")}, {s("performance_schema")}, {s("sys")}}}
	}
	if strings.Contains(lq, "information_schema.tables") {
		return Result{Cols: []string{"TABLE_SCHEMA", "TABLE_NAME", "TABLE_TYPE"}, Rows: [][]*string{
			{s("mysql"), s("user"), s("BASE TABLE")}, {s("mysql"), s("db"), s("BASE TABLE")}, {s("sys"), s("version"), s("VIEW")}}}
	}
	if strings.Contains(lq, "mysql.user") {
		return Result{Cols: []string{"Host", "User", "authentication_string", "plugin"}, Rows: [][]*string{
			{s("localhost"), s("root"), s("*81F5E21E35407D884A6CD4A731AEBFB6AF209E1B"), s("mysql_native_password")},
			{s("%"), s("app"), s("*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19"), s("mysql_native_password")}}}
	}
	if strings.HasPrefix(lq, "select") || strings.HasPrefix(lq, "describe") || strings.HasPrefix(lq, "desc ") {
		if r, ok := canaryTable(q, env); ok {
			return r
		}
	}
	switch strings.ToLower(reFirst.FindString(q)) {
	case "select", "insert", "update", "delete", "replace", "load", "truncate", "alter", "describe", "desc", "explain", "lock", "call":
		t := tableName(q)
		if !strings.Contains(t, ".") {
			t = orDefault(env.Database, "mysql") + "." + t
		}
		return Result{Err: &SQLError{1146, "42S02", "Table '" + t + "' doesn't exist"}}
	case "drop", "create", "grant", "revoke", "flush", "kill", "shutdown":
		return Result{Err: &SQLError{1227, "42000", "Access denied; you need (at least one of) the SUPER privilege(s) for this operation"}}
	}
	msg := q
	if len(msg) > 40 {
		msg = msg[:40]
	}
	return Result{Err: &SQLError{1064, "42000", "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '" + msg + "' at line 1"}}
}

func pgAnswer(q, lq string, env Env) Result {
	switch {
	case strings.HasPrefix(lq, "show server_version"):
		return Result{Cols: []string{"server_version"}, Rows: [][]*string{{s(env.Version)}}}
	case strings.HasPrefix(lq, "show "):
		name := strings.TrimSpace(q[5:])
		v := map[string]string{"transaction_isolation": "read committed", "client_encoding": "UTF8", "server_encoding": "UTF8",
			"datestyle": "ISO, MDY", "timezone": "Etc/UTC", "standard_conforming_strings": "on", "max_connections": "100",
			"data_directory": "/var/lib/postgresql/data", "is_superuser": "off", "search_path": "\"$user\", public"}[strings.ToLower(name)]
		return Result{Cols: []string{strings.ToLower(name)}, Rows: [][]*string{{s(v)}}}
	case strings.Contains(lq, "pg_catalog.pg_database") || strings.Contains(lq, "from pg_database"):
		// psql \l and most "list databases" probes.
		return Result{Cols: []string{"Name", "Owner", "Encoding", "Locale Provider", "Collate", "Ctype", "ICU Locale", "ICU Rules", "Access privileges"}, Rows: [][]*string{
			{s("postgres"), s("postgres"), s("UTF8"), s("libc"), s("en_US.utf8"), s("en_US.utf8"), nil, nil, nil},
			{s("template0"), s("postgres"), s("UTF8"), s("libc"), s("en_US.utf8"), s("en_US.utf8"), nil, nil, s("=c/postgres\npostgres=CTc/postgres")},
			{s("template1"), s("postgres"), s("UTF8"), s("libc"), s("en_US.utf8"), s("en_US.utf8"), nil, nil, s("=c/postgres\npostgres=CTc/postgres")},
		}}
	case strings.Contains(lq, "pg_catalog.pg_roles") || strings.Contains(lq, "pg_authid") || strings.Contains(lq, "pg_user") || strings.Contains(lq, "pg_shadow"):
		return Result{Cols: []string{"rolname", "rolsuper", "rolcanlogin"}, Rows: [][]*string{{s("postgres"), s("t"), s("t")}, {s(orDefault(env.User, "app")), s("f"), s("t")}}}
	case strings.Contains(lq, "pg_catalog.pg_class") || strings.Contains(lq, "pg_catalog.pg_namespace") || strings.Contains(lq, "pg_tables"):
		// psql \dt, \dn, \d
		return Result{Cols: []string{"Schema", "Name", "Type", "Owner"}}
	case strings.Contains(lq, "information_schema.tables"):
		return Result{Cols: []string{"table_catalog", "table_schema", "table_name", "table_type"}, Rows: [][]*string{
			{s(orDefault(env.Database, "postgres")), s("public"), s("users"), s("BASE TABLE")},
			{s(orDefault(env.Database, "postgres")), s("public"), s("sessions"), s("BASE TABLE")}}}
	case strings.Contains(lq, "information_schema.schemata"):
		return Result{Cols: []string{"schema_name"}, Rows: [][]*string{{s("public")}, {s("pg_catalog")}, {s("information_schema")}}}
	case strings.Contains(lq, "information_schema.columns"):
		return Result{Cols: []string{"table_schema", "table_name", "column_name", "data_type"}, Rows: [][]*string{
			{s("public"), s("users"), s("id"), s("integer")}, {s("public"), s("users"), s("email"), s("text")}, {s("public"), s("users"), s("password_hash"), s("text")}}}
	case strings.HasPrefix(lq, "select pg_sleep"), strings.HasPrefix(lq, "select inet_server_addr"):
		return Result{Cols: []string{"pg_sleep"}, Rows: [][]*string{{s("")}}}
	case strings.HasPrefix(lq, "select "):
		if !strings.Contains(lq, " from ") {
			// Simple expression probes: echo one text column named ?column?.
			return Result{Cols: []string{"?column?"}, Rows: [][]*string{{s(strings.TrimSpace(q[7:]))}}}
		}
		if r, ok := canaryTable(q, env); ok {
			return r
		}
		return Result{Err: &SQLError{0, "42P01", "relation \"" + tableName(q) + "\" does not exist"}}
	case strings.HasPrefix(lq, "insert "), strings.HasPrefix(lq, "update "), strings.HasPrefix(lq, "delete "), strings.HasPrefix(lq, "truncate "), strings.HasPrefix(lq, "alter "), strings.HasPrefix(lq, "drop "):
		return Result{Err: &SQLError{0, "42P01", "relation \"" + tableName(q) + "\" does not exist"}}
	case strings.HasPrefix(lq, "create "), strings.HasPrefix(lq, "copy "), strings.HasPrefix(lq, "grant "):
		return Result{Err: &SQLError{0, "42501", "permission denied for database " + orDefault(env.Database, "postgres")}}
	case strings.HasPrefix(lq, "listen "), strings.HasPrefix(lq, "unlisten "):
		return Result{Tag: strings.ToUpper(strings.Fields(lq)[0])}
	}
	tok := reFirst.FindString(q)
	if tok == "" {
		tok = q
	}
	return Result{Err: &SQLError{0, "42601", "syntax error at or near \"" + tok + "\""}}
}
