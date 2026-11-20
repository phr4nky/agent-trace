# MCP proxy

`agent-trace proxy` records an agent you already use, without changing its code. It sits
between an MCP client (Claude Code, Cursor, Claude Desktop, your own agent) and an MCP server.
It forwards the traffic, records every tool call as a trace, runs the rules after every event
and can block calls its policy denies.

```text
                ┌─stdio─▶ agent-trace proxy ─stdio─────────▶ MCP server (local command)
MCP client ─────┤                  │
(Claude Code, …)└─stdio─▶ agent-trace proxy ─streamable HTTP─▶ MCP server (remote URL)
                                   │
                                   ▼
                     one trace per client session (SQLite, PostgreSQL, MySQL)
                     agent-trace explore --latest --follow
```

The client starts one proxy per server. All proxies of one client session write into **one
trace**, so untrusted content that arrives through one server counts against privileged calls
to every other server (see [Sessions](#sessions-one-trace-across-servers)).

## A real-world example: the GitHub MCP issue injection

In May 2025, Invariant Labs showed this attack on the GitHub MCP server:

1. An attacker opens an issue in a victim's **public** repository. The issue text asks the agent
   to read all of the author's repositories and publish what it finds about the author.
2. The victim asks their agent to "look at the open issues".
3. The agent reads the issue, reads the victim's **private** repositories with the victim's own
   token, and opens a **public pull request** containing the private content.

No single call is wrong in isolation. What is wrong is the sequence: attacker-controlled text
enters the session, then a privileged write follows. That sequence is what the proxy checks.

### Setup

Wrap the server in the client's MCP configuration. For Claude Code (`.mcp.json` in the project, or
`claude mcp add`):

```json
{
  "mcpServers": {
    "github": {
      "command": "agent-trace",
      "args": [
        "--config", "/Users/me/.config/agent-trace/github.toml",
        "proxy", "--name", "github", "--",
        "docker", "run", "-i", "--rm", "-e", "GITHUB_PERSONAL_ACCESS_TOKEN",
        "ghcr.io/github/github-mcp-server"
      ],
      "env": { "GITHUB_PERSONAL_ACCESS_TOKEN": "…" }
    }
  }
}
```

```sh
claude mcp add github -- agent-trace --config ~/.config/agent-trace/github.toml \
  proxy --name github -- docker run -i --rm -e GITHUB_PERSONAL_ACCESS_TOKEN ghcr.io/github/github-mcp-server
```

Cursor (`~/.cursor/mcp.json`) and Claude Desktop (`claude_desktop_config.json`) use the same
`mcpServers` format. Desktop apps often do not have `~/.cargo/bin` on their `PATH`; use the
absolute path of `agent-trace` there.

The proxy passes its environment to the server unchanged, so the token reaches the server as
before. It is never written to the trace.

Use an absolute `--config` path: MCP clients start servers in a working directory you do not
control, so `./agent-trace.toml` may not be found.

The configuration (`examples/proxy/agent-trace.toml`):

```toml
[policy]
# Tools that write with the user's token.
privileged = ["create_pull_request", "create_or_update_file", "push_files", "create_issue",
              "add_issue_comment", "merge_pull_request"]

[proxy]
mode = "enforce"
# Results of these tools are written by strangers. Reading your own files is not.
taint_sources = ["get_issue", "list_issues", "get_issue_comments", "search_*",
                 "get_pull_request*", "list_pull_requests"]
```

Tool names differ between versions of the GitHub server. The proxy records the server's
`tools/list` answer, so `agent-trace trace show --latest --payload` shows the names to use.

### What the trace shows

Watch live with `agent-trace explore --latest --follow`:

| # | Event | What the proxy does |
|---|---|---|
| 1 | `agent_started` | session begins |
| 2 | `external_content_observed` `tools/list` (lower-trust) | tool descriptions recorded and scanned by AT-001/AT-005 (catches poisoned tool descriptions) |
| 3–7 | `get_issue` request, decision, execution, **result (lower-trust)**, completion | the issue text is now session context |
| 8–12 | `get_file_contents` on the private repository | allowed: not privileged |
| 13 | `tool_call_requested` `create_pull_request`, `context_event_ids` → the issue result | privileged tool after untrusted content |
| 14 | `tool_policy_decision` **deny** (`blocked`) | the call never reaches GitHub; the agent gets `BLOCKED by agent-trace proxy policy: …` |

Findings:

- **AT-002** (high severity, **medium confidence**, `blocked`): privileged tool requested with
  lower-trust content in the session. Confidence is medium because the link is session context
  (see below), not an observed cause.
- **AT-004** (`blocked`): the policy denial.
- **AT-001** fires only if the issue text matches one of its patterns ("ignore previous
  instructions", "send … to https://…", …). The text of the real attack sounded like a normal
  request and would not match. The block does not depend on it.
- **AT-003** does not fire here: it needs secrets the redactor recognises, and private source
  code is not one. The policy rule above is what stops this attack.

In `observe` mode the same session is forwarded unchanged; the decision is recorded as
`allow` with `"would_deny": true`, and AT-002 reports `executed`.

## Modes

| Mode | Denied call | Use it for |
|---|---|---|
| `observe` (default) | forwarded; decision recorded as `allow` with `would_deny` | learning what an agent does, tuning the config |
| `enforce` | answered with a tool error (`isError: true`); never sent to the server | protecting a session |

A call is denied when:

1. it is an outbound tool and a destination argument is not on the allowlist (same check as
   the lab and AT-003), or
2. it is a privileged tool (outbound tools count as privileged) and lower-trust content from a
   taint source was returned earlier in the session, or
3. its arguments carry a [canary token](canaries.md), whatever the tool.

## Causality: session context, not causes

The proxy sees tool traffic, not the model's context window. It cannot know whether the model
read a result before asking for the next tool. agent-trace never infers causality, so the proxy
records no `caused_by_event_id` for tool requests. Instead:

- every earlier result from a taint source is listed in the request's `context_event_ids`
  (at most the newest 256),
- the request carries `"link_basis": "session_context"` in its metadata,
- AT-002 and AT-006 report findings on such links with **medium** confidence and say why.

`taint_sources` decides which content counts. The default `["*"]` counts every tool result,
resource and prompt, which is safe but strict: in `enforce` mode, reading any file and then
writing anything is blocked. Narrow it to the tools whose output strangers can write.

Patterns use `*` as a wildcard and match:

| Content | Matched as |
|---|---|
| tool result | the tool name, e.g. `get_issue` |
| `resources/read` | `resource:<uri>`, e.g. `resource:file:///*` |
| `prompts/get` | `prompt:<name>` |

Tool descriptions from `tools/list` are recorded and scanned but never linked: they are part of
every session, so linking them would mark every privileged call.

## Configuration

`agent-trace.toml` is found in this order: `--config PATH`, `$AGENT_TRACE_CONFIG`,
`./agent-trace.toml`, `<data dir>/agent-trace.toml`. When a file is used, its path is printed on
stderr. A file with unknown keys or wrong types is an error.

```toml
[policy]                  # added to the built-in defaults, which cannot be removed
privileged = ["create_*"] # tool names, `*` wildcards
outbound = ["post_*"]     # tools that send data somewhere; destinations are checked
allow_destinations = ["hooks.corp.example", "*.corp.example"]  # `*.x` = subdomains of x

[proxy]
mode = "observe"          # or "enforce"; --mode overrides it
taint_sources = ["*"]
call_timeout_secs = 300   # --call-timeout overrides it
```

`analyze`, `import`, `export`, `explore` and `demo run` use the same `[policy]`, so a CI gate
judges a recorded trace the way the proxy did.

## Remote servers (streamable HTTP)

For a server reached by URL, pass `--url` instead of a command. The client still starts the
proxy over stdio; the proxy connects to the server.

```json
{
  "mcpServers": {
    "github": {
      "command": "agent-trace",
      "args": ["--config", "/Users/me/.config/agent-trace/github.toml",
               "proxy", "--name", "github",
               "--url", "https://api.githubcopilot.com/mcp/",
               "--bearer-token-env", "GITHUB_PAT"],
      "env": { "GITHUB_PAT": "…" }
    }
  }
}
```

- **https only.** Plain `http://` is accepted for `localhost` and loopback addresses only, so
  tool arguments, results and credentials never cross a network in clear text.
- **Credentials come from the environment.** `--bearer-token-env VAR` sends
  `Authorization: Bearer $VAR`; `--header-env NAME=VAR` sends any other header (repeatable).
  There is no option that takes a secret value on the command line, where other local users
  could read it in the process list. Tokens and header values are never recorded; the trace
  stores the URL without credentials, query or fragment.
- Redirects are followed only within the same origin (307/308), so the session and headers are
  never replayed to another host.
- The proxy itself still listens on nothing: clients talk to it over stdio only.

## Sessions: one trace across servers

An MCP client starts one proxy process per configured server. Those proxies find each other
through a **session key** and write into the same trace:

| Key | When |
|---|---|
| `--session KEY` or `$AGENT_TRACE_SESSION` | set explicitly; proxies with the same key share a trace |
| the MCP client process (PID and start time) | default on Linux and macOS: every proxy the same client process started |
| none (`--no-session`) | a trace of its own, named `proxy/<name>` (the default on Windows) |

A shared trace is named `proxy-session/<id>`. Each proxy records an `mcp-server-connected`
event (server, endpoint, mode, taint sources, policy) and its events below it. The trace is
`running` while any proxy is connected and `completed` when the last one disconnects.

Writers are serialized with a file lock per trace in `<data dir>/proxy-sessions/`, and every
access loads the trace from the store, so all proxies see each other's events. Taint labels
name the proxy and the source, e.g. `issues:get_issue`, so a denial says where the content came
from:

```text
BLOCKED by agent-trace proxy policy: privileged tool requested after lower-trust content
entered the session (from issues:get_issue)
```

If the store fails, a proxy in `enforce` mode answers tool calls with an error instead of
forwarding them unchecked (it cannot see the session's history); in `observe` mode it forwards
and logs the error on stderr.

## Command

```text
agent-trace [--config PATH] [--data-dir PATH] [--database-url URL] proxy
            [--name NAME] [--mode observe|enforce] [--call-timeout SECONDS]
            [--session KEY | --no-session]
            ( --url URL [--bearer-token-env VAR] [--header-env NAME=VAR]...
            | -- <server command> [args...] )
```

- Stdout carries only MCP messages. Status lines (trace ID, database, findings at the end) go to
  stderr, which MCP clients show in their server logs.
- Execution mode `live`. A proxy's connection ends when the client disconnects or the proxy
  gets Ctrl-C or SIGTERM (`ended_by` on its `mcp-server-disconnected` event).
- The trace records the client name and version; each connection records its server, endpoint,
  transport, mode, taint sources and effective policy.

## Limits in this version

- **Upstream only.** The proxy reaches servers over stdio or streamable HTTP, but it accepts
  clients over stdio only; it opens no listening port.
- **Session detection needs a common parent.** Clients that start each server through a
  separate wrapper process, and all clients on Windows, need `--session KEY` to share a trace.
- **A crashed proxy keeps the trace `running`**: the connection count is only decremented on a
  clean exit or a signal.
- **The client's built-in tools are invisible.** Claude Code's Bash, Write or WebFetch never
  pass through an MCP server. Use the [Claude Code hooks](claude-code-hooks.md) for those.
- **Forwarded, not recorded:** `resources/list`, `resources/templates/list`, `prompts/list`.
- **Not forwarded:** resource subscriptions, list-changed notifications, logging, completions,
  and requests from the server to the client (sampling, elicitation, roots). The proxy announces
  only what it forwards, so clients do not rely on the rest.
- Only the text of results is recorded; images and binary resource contents are counted, not
  stored.
