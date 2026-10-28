# honeypot-sql

MIT licensed. Public home: <https://github.com/ErwanBAILLON/honeypot-sql> (mirror; development happens on a self-hosted Gitea whose CI builds and deploys the image). The `helm/` chart and `.gitea/` workflow are the author's homelab deployment, kept as a worked example.

A low-interaction database honeypot. It speaks enough of the **MySQL** (3306)
and **PostgreSQL** (5432) wire protocols to complete the handshake, accepts any
credentials (or only a honeytoken list), records everything the client does,
answers a handful of common queries so bots keep talking, and emits one JSON log
line per touch and per credential attempt that **CrowdSec** turns into a ban.

Single static Go binary, no CGO, runs as non-root on distroless.

## What it does, and what it never does

| Does | Never does |
|---|---|
| MySQL handshake v10, `mysql_native_password`, `AuthSwitchRequest` for `caching_sha2_password` clients, connect attributes, text result sets | Execute SQL. Every answer is a static table from `internal/fakedb` |
| PostgreSQL startup v3, `SSLRequest` answered `N`, cleartext or md5 password, simple **and** extended query protocol (Parse/Bind/Execute, what pgx, psycopg, JDBC use) | Open outbound connections (NetworkPolicy: DNS + the state database only) |
| Records user, database, password as sent (MySQL: plaintext when it matches a honeytoken or a common password, otherwise the SHA1 scramble), client capabilities, `application_name`, every query with timing, bytes in/out | Keep state on the attacker's behalf, run prepared statements, speak TLS |
| Attributes the source IP to a country and autonomous system **offline**, from a local ip2asn table, and can **tarpit** (slow its own replies) to keep a bot engaged | Call any geolocation API, or open any connection *toward* the attacker. Attribution reads a local file; the tarpit only delays our own writes |
| Per-read timeout 30 s, session cap 10 min, 200 queries, 1 MiB packets, 500 concurrent connections per listener (extra connections are closed at accept) | Retaliate. Decisions are made by CrowdSec from the log line, nothing else |
| Bounded storage: client blobs (auth response, bad handshake, connect attrs, startup params) are kept up to 256 bytes verbatim plus length and sha256; any event payload over 16 KiB or client_info over 32 KiB is replaced by a summary. A 1 MiB packet costs a few KB in the database, never megabytes | Persist what the client sent as is |

Threat model: an unauthenticated network attacker. The process has no secrets
other than its own database URL and dashboard password, no shell, no writable
filesystem, no service-account token. The worst case is a protocol bug that
crashes the pod, which Kubernetes restarts.

## Layout

```
cmd/honeypot-sql       serve | stats | version
internal/mysqlhp       MySQL packets + server
internal/pghp          PostgreSQL messages + server
internal/fakedb        canned answers (SELECT VERSION(), SHOW DATABASES, \l, information_schema...)
internal/hpcore        accept loop, limits, session recorder, JSON log lines
internal/store         Postgres (pgx) and in-memory stores
internal/web           dashboard (html/template, no JS), JSON API, probes, /metrics
tests/                 integration tests with go-sql-driver/mysql and pgx
helm/                  chart (ArgoCD app `honeypot-sql`, namespace `projects`)
```

## Configuration

Flags or environment (`honeypot-sql serve -h`):

| Env | Default | Meaning |
|---|---|---|
| `HONEYPOT_MYSQL_ADDR` | `:3306` | MySQL listener (empty = off) |
| `HONEYPOT_PG_ADDR` | `:5432` | PostgreSQL listener (empty = off) |
| `HONEYPOT_HTTP_ADDR` | `:8080` | dashboard |
| `HONEYPOT_MYSQL_VERSION` / `HONEYPOT_PG_VERSION` | `8.0.36` / `16.3` | advertised versions |
| `HONEYPOT_PG_AUTH` | `cleartext` | `cleartext` records the password; `md5` records only the hash |
| `HONEYPOT_PASSWORDS` | empty | comma-separated honeytokens. Empty = accept every credential |
| `HONEYPOT_MAX_CONNS` | `500` | concurrent connections per listener |
| `DATABASE_URL` | empty | Postgres DSN; empty = in-memory store (tests, local runs) |
| `HONEYPOT_TARPIT` | `0` | delay before each reply (e.g. `2s`); keeps attackers engaged. See Tarpit |
| `HONEYPOT_IP2ASN` | empty | path to an ip2asn table for offline country/ASN attribution. See Attribution |
| `ADMIN_USER` / `ADMIN_PASSWORD` | empty | dashboard basic auth. Empty = dashboard refuses everything |

Local run without a database:

```sh
go run ./cmd/honeypot-sql serve -mysql :13306 -pg :15432 -http :18080
ADMIN_USER=a ADMIN_PASSWORD=b go run ./cmd/honeypot-sql serve ...
mysql -h 127.0.0.1 -P 13306 -u root -proot -e 'select version(); show databases'
psql 'postgres://x:y@127.0.0.1:15432/db?sslmode=disable' -c '\l'
```

## Attribution (where the attack comes from)

The honeypot can label every session with the source country and autonomous
system (number and organisation), entirely offline. It reads the public-domain
**ip2asn** table from <https://iptoasn.com> — a TSV of
`range_start  range_end  AS_number  country_code  AS_description`, plain or
gzip — mounted locally and pointed at by `HONEYPOT_IP2ASN`. Ranges are sorted
once and looked up by binary search (`internal/geoip`); IPv4 and IPv6 are both
covered. No network call is ever made: this preserves the "never opens outbound
connections" invariant, and the NetworkPolicy still blocks everything but DNS
and the state database.

When the file is absent the feature is simply off and the honeypot behaves
exactly as before. When present, the country and AS appear on the dashboard
(top countries, top networks, and per session) and in both JSON log lines
(`sql_honeypot_touch`, `sql_honeypot_auth`), so CrowdSec scenarios can match on
them.

```sh
curl -sO https://iptoasn.com/data/ip2asn-combined.tsv.gz   # ~5 MB, refresh when you like
go run ./cmd/honeypot-sql serve ... -ip2asn ip2asn-combined.tsv.gz
```

In the cluster, bake the file into the image at build time (the build runner
has network; the running honeypot never does) or mount it read-only, then set
`HONEYPOT_IP2ASN` to its path. The table is redistributable (RouteViews data,
public domain).

## Tarpit (keeping the attacker engaged)

With `HONEYPOT_TARPIT` set to a duration (e.g. `-tarpit 2s`), the honeypot waits
that long — plus up to 50 % jitter — before each reply in the command/query
loop, so a bot stays connected and busy against us instead of moving on. It is
off by default (`0`).

This only ever **slows our own writes**; it never opens or holds anything
toward the attacker. The session cap (`-session-max`, 10 min) still bounds the
whole exchange, and the hard deadline fires even mid-delay, so a tarpit can only
make a session end sooner than its cap, never run forever. The cost is capacity:
a stalled session holds its connection slot longer, so with a busy tarpit you
want a higher `HONEYPOT_MAX_CONNS` or you accept fewer concurrent attackers.
The handshake itself is left at full speed so clients complete auth and we
capture the credentials before the stalling begins.

## Tests

```sh
go vet ./... && go test -race ./...
```

`internal/*` tests cover the codecs (handshake layout, lenenc, OK/ERR/EOF,
startup, RowDescription/DataRow, md5), the ip2asn lookup (v4, v6, gaps, nil DB)
and the tarpit (off is instant, a cancelled context wakes it, a set delay is
honoured). `tests/` starts both listeners in-process with the memory store and
connects with the real client libraries: handshake, auth, `SELECT VERSION()`,
`SHOW DATABASES`, `\l` query, error SQLSTATEs, the SSLRequest fallback of pgx,
honeytoken rejection, garbage input, the dashboard and its basic auth. CI runs
the same before building the image.

## Deployment (homelab)

- Image: `git.ebaillon.fr/infra/honeypot-sql:0.1.<run>` built by Gitea Actions
  (`.gitea/workflows/build.yaml`), which then bumps `helm/values.yaml`.
- ArgoCD application `honeypot-sql` → namespace `projects`, auto-sync.
- Secrets: Vault `secret/honeypot-sql/main` (`DATABASE_URL`, `ADMIN_USER`,
  `ADMIN_PASSWORD`, optional `HONEYPOT_PASSWORDS`) synced by ExternalSecrets.
- State: database `honeypot_sql` on the shared CloudNativePG cluster. Tables
  `sessions` and `events` are created by the binary on start.
- Dashboard: `https://honeypot.ebaillon.fr` (LAN-only DNS, Traefik, Let's Encrypt).
- Honeypot ports: Service `honeypot-sql-trap` of type NodePort,
  `192.168.1.150:30306` (MySQL) and `192.168.1.150:30432` (PostgreSQL), with
  `externalTrafficPolicy: Local` so the real client IP is recorded. The
  apiserver uses the default 30000-32767 range, hence 30432 rather than 35432.

### Catching Internet scanners

Nothing on the Internet reaches the honeypot until the box forwards
`WAN:3306 -> 192.168.1.150:30306` and `WAN:5432 -> 192.168.1.150:30432`.
That is a deliberate manual step: once done, every bot hitting those ports is
banned by CrowdSec on the Traefik bouncer within seconds, and LAN clients are
whitelisted so a mistyped `psql` from the LAN does not ban your laptop.

## Seeing captures

- Dashboard `/`: counters, top IPs, usernames, passwords, queries, last 50
  sessions; `/sessions/<id>` shows every event with timing.
- JSON: `/api/sessions?limit=100`, `/api/sessions/<id>`, `/api/stats`.
- Prometheus: `/metrics` (`honeypot_sessions_total{proto}`,
  `honeypot_auth_attempts_total{proto}`, `honeypot_queries_total{proto}`,
  `honeypot_rejected_total{proto}`, `honeypot_active_connections`).
- CLI inside the pod image: `honeypot-sql stats` (needs `DATABASE_URL`).
- Pod log (stdout): one JSON line per event, e.g.

```json
{"event":"sql_honeypot_auth","proto":"postgres","remote_ip":"203.0.113.9","remote_port":51834,"session_id":42,"username":"postgres","database":"postgres","password_seen":"postgres","ts":"2026-10-05T09:12:33.120Z"}
```

## How CrowdSec uses it

Configured in `orgs/infra/crowdsec/values.yaml`:

1. **Acquisition**: the agent tails `/var/log/containers/honeypot-sql-*_projects_*.log`
   with label `program: honeypot-sql` (CRI format, parsed by `crowdsecurity/cri-logs`).
2. **Parser** `homelab/sql-honeypot-logs` (s01-parse): unmarshals the JSON line,
   sets `source_ip`, `service=sql-honeypot`, `log_type=sql_honeypot_touch|sql_honeypot_auth`,
   plus `username`/`proto` meta for the alert.
3. **Scenario** `homelab/sql-honeypot-touch` (type trigger): one event = one
   alert. Any IP talking to a database honeypot is hostile by definition.
4. Whitelist `homelab/trusted-networks` (s02-enrich) drops LAN/pod/service CIDRs
   before the scenario, so LAN tests produce parsed lines but no decision.
5. Decision duration comes from the LAPI profile (default 4h). To ban longer,
   add a profile matching `Alert.GetScenario() == "homelab/sql-honeypot-touch"`
   with `duration: 24h` in `config."profiles.yaml"` (LAPI restart).

Check: `cscli metrics` (acquisition line for the honeypot log, scenario line),
`cscli explain --log '<CRI line>' --type containerd --labels program:honeypot-sql`,
`cscli alerts list`.

## Legal note

Running a honeypot on infrastructure you own, to observe connections made to
it, is lawful in France: the connecting party initiates the access, nothing is
intercepted on a third party's network, and no code is executed on the
attacker's machine. Keep it that way: do not "hack back", do not publish
captured credentials together with IPs in a way that identifies individuals,
and purge the `sessions` table on a retention schedule (IP addresses are
personal data under the GDPR; a security-purpose legitimate interest covers
collection, not indefinite storage).
