# Team server and web UI

`agent-trace-server` collects the traces of many recorders in one database and shows them in a
web UI: pick a source (a laptop, a CI runner), pick one of its traces, and its causal graph opens
next to the list.

```text
Laptop A ─┐  agent-trace (hook / proxy): decides, redacts, stores locally (SQLite)
Laptop B ─┼─ agent-trace ship ──HTTPS, source token──┐
CI runner ┘                                           ▼
                              agent-trace-server (Rust): checks, redacts again,
                              analyzes, records the source and its address
                                           │
                                      PostgreSQL
                                           │ read API
                              web UI (Angular + SwipyUI): source → traces → graph
```

The recorder stays where the agent runs: it must decide before a tool call runs, in
milliseconds and also offline, and it redacts secrets before anything is stored or leaves the
machine. `ship` sends what is new afterwards (store and forward), so a slow or unreachable server
never delays a tool call and nothing is lost while it is down.

## Demo in three steps

**1. Start the server and the database**

```sh
docker compose up -d --build
docker compose exec server agent-trace-server source add laptop      # prints the token once
docker compose exec server agent-trace-server source add ci-runner
```

The web UI is on <http://localhost:8080>.

**2. Record and send**

```sh
export AGENT_TRACE_SHIP_TOKEN=ats_…            # the token of "laptop"
agent-trace demo run --scenario exfil-attempt
agent-trace ship --to http://localhost:8080

# a second source, e.g. a CI runner (another data directory and token)
AGENT_TRACE_SHIP_TOKEN=ats_… agent-trace --data-dir /tmp/ci demo run --scenario multi-agent-handoff
AGENT_TRACE_SHIP_TOKEN=ats_… agent-trace --data-dir /tmp/ci ship --to http://localhost:8080
```

With Claude Code hooks running, `agent-trace ship --to http://localhost:8080 --follow` in a second
terminal sends new events every two seconds.

**3. Open the UI.** Choose the source, then a trace: the table shows severity, findings, events
and status; the causal graph of the selected trace opens next to it (click a finding to light up
its evidence path, a step for its details). The view refreshes every four seconds, so a running
session grows while you watch. `?source=NAME` in the address opens that source, so a view can be
linked.

## Without Docker

```sh
cd ui && npm ci && npm run build && cd ..
cargo run -p agent-trace-server -- source add laptop
cargo run -p agent-trace-server -- serve --ui-dir ui/dist/agent-trace-ui/browser
```

Without `--database-url` (or `$AGENT_TRACE_DATABASE_URL`) the server uses SQLite in
`--data-dir` (default: the local data directory, `agent-trace-server/server.sqlite3`). For UI
development, `cd ui && npm start` serves the app on <http://localhost:4200> and proxies `/api` to
`http://127.0.0.1:8080`.

## Sending traces: `agent-trace ship`

```text
agent-trace ship [--to URL] [--follow] [--interval SECONDS]
```

- **Token:** from `$AGENT_TRACE_SHIP_TOKEN`, or the variable named by `token_env` in `[ship]`.
  Never put it in a command line or a file in a repository.
- **Server:** `--to`, or `url` in `[ship]`. Only `https://`, or plain http to a loopback host;
  redirects are not followed, so the token is never sent elsewhere.
- **Token check first:** `ship` asks the server which source the token belongs to
  (`GET /api/v1/whoami`) and stops with an error if the token is unknown, also when there is
  nothing new to send.
- **What is sent:** for each local trace, the current header and the events after the last one
  the server confirmed, in batches of up to 2,000 events. The events are already redacted.
- **Progress:** `<data dir>/ship/<server>.json` remembers per trace the last confirmed event and
  status. A trace is sent again when it grows or its status changes. If the server has another
  state (its database was reset), it says where to continue and `ship` resumes there.

```toml
[ship]
url = "https://trace.example.com"
token_env = "AGENT_TRACE_SHIP_TOKEN"   # default
```

## The server

```text
agent-trace-server [--database-url URL] [--data-dir PATH] [--config agent-trace.toml]
                   serve [--listen ADDR] [--ui-dir PATH] [--allow-unauthenticated-reads]
                         [--trust-forwarded-for]
agent-trace-server source add NAME | list | remove NAME
```

**Sources** are the recorders that may send traces. `source add` prints a random token once
(`ats_` and 64 hex digits); the server stores only its SHA-256. `source remove` revokes the token;
the traces of the source stay. Each trace belongs to the source that sent it first: no other
source can extend or overwrite it.

**What happens to a batch** (`POST /api/v1/ingest`), as with `import`:

1. The token is mapped to its source (unknown token: 401).
2. The batch must continue the stored trace: events in sequence, no gap, a retried event must be
   the same event (otherwise 409 with the sequence number to continue from).
3. Everything is redacted again with the server's redaction rules.
4. The whole trace must stay valid (schema, causal links, sequence numbers; otherwise 422).
5. The findings are computed on the server with its rules. A recorder never sends findings.
6. The source's last contact and address are updated.

**Rules and redaction:** `--config` reads `[policy]`, `[[rules]]` and `[redaction]` from an
`agent-trace.toml` and ignores its other tables, so recorders and server can share one file and
get the same findings.

**Database:** SQLite for a single host, PostgreSQL (or MariaDB/MySQL) for a team, through the
same storage layer as the CLI. The server adds a `sources` table and the source of each trace.

**Client address:** the address the batch came from. In Docker it is the address of Docker's
network gateway for clients on the host. Behind a reverse proxy, `--trust-forwarded-for` takes it
from `X-Forwarded-For` (only if the proxy sets that header itself). An IP address is personal
data under the GDPR: the UI shows it as an attribute of a source, not as the key.

## API

| Method and path | Auth | Answer |
|---|---|---|
| `POST /api/v1/ingest` | source token | `{trace_id, stored_seq, findings, redactions}`; 401, 409 (`stored_seq`), 422 |
| `GET /api/v1/whoami` | source token | `{source_id, name}` |
| `GET /api/v1/sources` | none (see below) | sources with `traces`, `last_seen_at`, `last_ip` |
| `GET /api/v1/traces?source=ID` | none | the source's traces: name, status, events, findings, highest severity |
| `GET /api/v1/traces/{id}` | none | the trace with its findings (the `export --format json` report) |
| `GET /api/v1/traces/{id}/graph` | none | the causal graph page (as `agent-trace graph`) |
| `GET /api/v1/health` | none | `{status, version}` |

Request bodies are limited to 64 MiB and 2,000 events per batch; a trace to 100,000 events.

## Security

- **No login for reads yet.** `serve` listens on `127.0.0.1` by default and refuses a non-loopback
  address unless `--allow-unauthenticated-reads` is given; `docker-compose.yml` publishes the port
  on `127.0.0.1` only. For a team, put the server behind your own access control (VPN, a reverse
  proxy with SSO) until login and roles exist.
- **Sources authenticate** with tokens that are random, shown once and stored hashed. Ingest is
  never anonymous.
- **Content is attacker-controlled.** Recorded tool results contain whatever a web page or an
  injected document said. The UI renders it as text only (Angular bindings, no `innerHTML`); the
  graph page keeps its own Content-Security-Policy (only its own hashed script and style, no
  connections) and runs in a frame with `sandbox="allow-scripts"`, without access to the app.
  The app itself is served with `script-src 'self'`, `connect-src 'self'`, `frame-ancestors
  'none'`; its build inlines no scripts or event handlers.
- **Transport:** `ship` uses HTTPS (plain http only to loopback) and never follows redirects. The
  server speaks plain HTTP; terminate TLS in front of it for anything beyond one host.
- **Evidence:** the database is not tamper-evident; signed JSONL exports (`export --sign`) are.

## Not yet

Login and roles (which user sees which sources), search across traces, live updates by push
(the UI polls every four seconds), paging of very large traces in the graph, rate limits per
source, and signed batches so the server can verify the recorder's signature.
