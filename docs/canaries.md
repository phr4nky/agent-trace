# Canary tokens

Most findings of agent-trace are indicators: content that looks like an injection, a privileged
call that follows untrusted content. A canary token turns a suspicion into evidence. You plant a
decoy secret where an attacker would look for real ones, and agent-trace reports every tool call
that carries it. No legitimate task ever uses a decoy, so a canary in a tool call means the
agent was moving a secret it read.

Example: in a [demonstration against the Supabase MCP server][supabase], a support ticket told a
coding agent to read the `integration_tokens` table and write the rows back into the ticket,
where the attacker could read them. With a canary row in that table, the `add_ticket_comment`
call that carries it is reported as AT-007, and in enforce mode it is denied before it reaches
the server.

## Setup

1. Create a decoy. `agent-trace canary new` prints a fresh value in a realistic shape and the
   entry for `agent-trace.toml` (it writes nothing):

   ```sh
   agent-trace canary new aws-decoy                  # AKIA… (AWS access key ID), the default
   agent-trace canary new gh-decoy --kind github     # ghp_…
   agent-trace canary new api-decoy --kind hex       # 40 hex characters
   agent-trace canary new db-decoy --kind password   # 24 characters
   ```

2. Plant the value where an attacker would look: a line in a `.env` file the agent can read, a
   row in a table the agent can query (`integration_tokens`, `api_keys`), a token in a document
   or wiki page, an entry in a test fixture.

3. Configure it where the agent **cannot** read it. An agent that reads the canary list learns
   which secrets are decoys, and so does an attacker who steers it. Use the `agent-trace.toml` in
   the data directory or a file passed with `--config`, not a file in the repository. Better
   still, keep the value out of every file and read it from the environment:

   ```toml
   [[canaries]]
   name = "aws-decoy"
   env = "AGENT_TRACE_CANARY_AWS_DECOY"   # value read from this variable

   [[canaries]]
   name = "ticket-token"
   value = "tok_live_8Jq2…"              # or the value itself
   ```

   For the proxy and the hooks, the variable must be set in the environment they run in (the
   MCP client's server config, or the environment Claude Code starts hooks with).

4. Check what is active: `agent-trace canary list` prints the configured names (never values).

## What happens

- **Recording.** Before an event is redacted and stored, its payload and metadata are searched
  for every canary value, as written and percent-encoded (as in a URL query). The names of the
  canaries found are kept in the event metadata (`"canaries": ["aws-decoy"]`). The values
  themselves are replaced with `[REDACTED:canary]`, even when they look like a known secret
  format. Stored traces, exports, logs and the graph never contain a canary value. The same
  happens on `import`.
- **Detection: AT-007.** A `tool_call_requested` event whose arguments carry a canary is a
  finding with high confidence: **critical** when the call was executed or only attempted,
  **high** when it was blocked (the agent was steered, but nothing left). The evidence starts at
  the event where the canary first entered the trace (the file read, the query result), so the
  evidence path shows how it got from there into the call. Analysis needs only the stored
  names: a trace can be analyzed on a machine that does not know the values.
- **Enforcement.** The policy gate denies any tool call whose arguments carry a canary,
  whatever the tool: privileged or not, allowlisted destination or not. With `proxy --mode
  enforce` and `hook --mode enforce` the call never runs; the agent gets a denial that names
  the canary but not its value. In `observe` mode the call runs and the decision is recorded
  with `would_deny`.

## Limits

- Only literal occurrences are found: the value as written or percent-encoded. A value that is
  transformed first (base64, split in parts, reversed, hashed) is not recognized. A shell
  command that reads the file itself (`curl -d @.env …`) carries the file name, not the value;
  the policy for privileged tools and AT-002 cover that case.
- A canary is found in what agent-trace records: tool calls through the proxy or the hooks,
  events your own recorder writes. What the agent does outside of that is not seen.
- Values must be 12 to 1024 characters without spaces, so they do not match ordinary text by
  chance. Names are 1 to 64 lowercase letters, digits, `-`, `_` or `.`, and both must be unique.
- Canaries configured later do not change traces recorded earlier: the value was already
  replaced (if it matched a secret pattern) or kept, and no name was stored.
- Names in imported traces are taken as they are. A forged name can only add a finding, never
  hide one.
- Realistic decoys may trigger secret scanners (for example GitHub push protection) if you
  commit them. That is fine for a decoy, but keep it in mind before planting one in a public
  repository.

[supabase]: https://generalanalysis.com/blog/supabase-mcp-blog
