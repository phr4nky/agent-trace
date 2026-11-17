# Using agent-trace in Jenkins

This guide adds a security gate for AI agents to a Jenkins build. When your agent's integration tests
produce traces where untrusted content triggered a privileged tool call, an exfiltration attempt or
another finding, the build turns red (or yellow, if you prefer). The redacted evidence is archived
with the build.

```
agent tests ──► traces/*.jsonl ──► agent-trace import ──► analyze --fail-on high ──► exit 0 / 2
                                          │                                        │
                                          └──► reports/*.json, *.txt ──► archived   └──► SUCCESS / FAILURE / UNSTABLE
```

Ready-to-use files:

| File | Purpose |
|---|---|
| [`examples/ci/Jenkinsfile`](../examples/ci/Jenkinsfile) | Complete declarative pipeline: install, gate, optional model check, artifacts |
| [`examples/ci/agent-trace-gate.sh`](../examples/ci/agent-trace-gate.sh) | POSIX shell script that imports, exports and analyzes every trace in a directory |

Both are also shipped in every release archive under `examples/ci/`.

---

## 1. Prerequisites

- A Linux build agent (x86_64) with `curl` and `tar`, or Docker. On Windows agents, see
  [Windows agents](#windows-agents).
- Jenkins with the Pipeline plugin. *Credentials Binding* is needed only for the optional model check
  or a shared database.
- Your agent writes **one JSONL trace per test run** into a directory, `traces/` in the examples. How to
  produce these traces is described in
  [Recording your own agent](../README.md#recording-your-own-agent).
  [`examples/ci/minimal-trace.jsonl`](../examples/ci/minimal-trace.jsonl) is a complete example.

No Rust toolchain is required on the agent if you use the release binary.

## 2. Install agent-trace on the agent

**Option A: release binary (recommended).** Download it once per workspace and keep it as a cache:

```bash
curl -fsSL "https://github.com/phr4nky/agent-trace/releases/download/v1.4.0/agent-trace-v1.4.0-x86_64-unknown-linux-gnu.tar.gz" \
  | tar -xz -C .agent-trace/bin --strip-components=1
```

**Option B: cargo.** Use this when the agent already has Rust:

```bash
cargo install --locked --git https://github.com/phr4nky/agent-trace --tag v1.4.0 agent-trace-cli
```

**Option C: Docker agent.** Run the pipeline in a container that has `curl`, then use option A:

```groovy
agent { docker { image 'buildpack-deps:bookworm-curl' } }
```

Pin the version. Rules can change between releases, and an unpinned upgrade could turn a green
build red without any change on your side.

## 3. The pipeline

Copy [`examples/ci/Jenkinsfile`](../examples/ci/Jenkinsfile) into your repository and replace
`https://github.com/phr4nky/agent-trace` and `./scripts/run-agent-tests.sh`. The core is only this:

```groovy
pipeline {
    agent { label 'linux' }
    environment {
        AGENT_TRACE_DATA_DIR = "${WORKSPACE}/.agent-trace/data-${BUILD_NUMBER}"
    }
    stages {
        stage('Agent tests') {
            steps { sh './scripts/run-agent-tests.sh' }      // writes traces/*.jsonl
        }
        stage('agent-trace gate') {
            steps {
                script {
                    def code = sh(returnStatus: true,
                                  script: 'sh agent-trace-gate.sh traces reports high')
                    if (code == 2)      { error('agent-trace: security findings, see reports/') }
                    else if (code != 0) { error("agent-trace gate failed (exit ${code})") }
                }
            }
        }
    }
    post {
        always { archiveArtifacts artifacts: 'reports/**', allowEmptyArchive: true }
    }
}
```

`returnStatus: true` is important. Without it Jenkins aborts the step on any non-zero exit code,
and you can no longer tell *findings* (2) from a *broken setup* (1).

### What the gate script does

For every `traces/*.jsonl`:

1. `agent-trace import --fail-on <threshold>`: validates the file, redacts it again, computes
   findings locally and writes them to `reports/<name>.txt` and the console. Findings stored in the
   file are ignored. The exit code is decided on this validated import, so another writer of a
   shared database cannot change the verdict.
2. `agent-trace export <id> --format jsonl`: writes the redacted trace to `reports/<name>.jsonl`.

It addresses each trace by the ID that `import` prints, not by `--latest`, so parallel builds on a
shared database cannot mix up traces.

| Exit code | Meaning | Suggested build result |
|---|---|---|
| `0` | No finding at or above the threshold | SUCCESS |
| `1` | Error: no traces, invalid or tampered trace, database unreachable | FAILURE |
| `2` | At least one finding at or above the threshold | FAILURE or UNSTABLE |

Arguments: `agent-trace-gate.sh [TRACE_DIR=traces] [REPORT_DIR=reports] [THRESHOLD=high]`. Set the
`AGENT_TRACE` environment variable to use a binary that is not on `PATH`.

### FAILURE or UNSTABLE?

The example Jenkinsfile has a parameter for this:

- **FAILURE** blocks merges. Use it when a finding is a real regression, which is the normal case
  for `high`.
- **UNSTABLE** gives a yellow build that still lets the change through. This suits a gentle rollout
  (start with `UNSTABLE`, switch to `FAILURE` later) or `--fail-on medium`, which also fails on
  suspicious content alone.

### Choosing the threshold

| `--fail-on` | Fails on |
|---|---|
| `high` (recommended) | Trust-boundary crossings (AT-002), cross-agent taint (AT-006), exfiltration of sensitive data (AT-003) |
| `medium` | Also injection-like text in untrusted content (AT-001), authority spoofing (AT-005) and policy denials (AT-004) |
| `low` | Everything |

`critical` is accepted as well, but no rule in v1.4.0 raises a critical finding, so a `critical`
gate never fails today.

## 4. Evidence in the build

`archiveArtifacts` stores `reports/` with every build, including failed ones (`post { always … }`):

- `reports/<trace>.txt` contains the findings with their evidence chain, for example
  `evidence: #2 → #3 → #4`.
- `reports/<trace>.jsonl` contains the full redacted trace. You can download it and inspect it
  locally. Findings are recomputed on import:

  ```bash
  agent-trace import --input minimal-trace.jsonl
  agent-trace explore --latest
  ```

Secrets were redacted before anything was written, so the artifacts can be shared with a security
team. The console output is redacted as well.

## 5. Variants

### Freestyle job (no pipeline)

1. Add a build step **Execute shell**:

   ```bash
   ./scripts/run-agent-tests.sh
   sh .agent-trace/bin/examples/ci/agent-trace-gate.sh traces reports high
   ```

2. Under **Advanced…**, set **Exit code to set build unstable** to `2`. Findings then make the build
   yellow, while errors (exit code `1`) still make it red. Leave the field empty if findings should
   make the build red.
3. Post-build action **Archive the artifacts**: `reports/**`.

### Keeping history in a shared database

By default, each build uses its own SQLite store, and the pipeline deletes it in `post { cleanup }`.
To compare findings across builds, point all builds at PostgreSQL or MariaDB/MySQL instead.
TLS is enabled automatically for non-loopback hosts.

Bind the credential only around the gate stage, not in the pipeline-wide `environment`. Otherwise
the agent tests, which run code from the change being built, can read the database password:

```groovy
stage('agent-trace gate') {
    when { not { changeRequest() } }   // untrusted pull requests use the per-build SQLite store
    steps {
        withCredentials([string(credentialsId: 'agent-trace-db-url', variable: 'AGENT_TRACE_DATABASE_URL')]) {
            sh 'sh "$AGENT_TRACE_HOME/examples/ci/agent-trace-gate.sh" traces reports "$FAIL_ON"'
        }
    }
}
```

Add a second gate stage with `when { changeRequest() }` and no credential, so pull requests are
still checked.

The secret should be a full URL, for example
`postgres://agent_trace:…@db.internal:5432/agent_trace?sslmode=require`. agent-trace redacts the
password in its own output, and Jenkins masks the credential in the log.

Note: a trace ID can be stored only once, because stored traces are never silently overwritten.
Real agents create a new ID for every run. If your tests replay *fixed* trace files, use the
per-build SQLite store, or the rebuild fails with `trace … already exists` (exit code 1).

### Model regression check

With `MODEL_CHECK=true`, the example pipeline runs the `exfil-attempt` lab scenario against a real
model and marks the build **UNSTABLE** if the model tried to exfiltrate. This tells you whether a
new model version or a changed prompt makes the agent easier to manipulate.

1. Under *Manage Jenkins → Credentials*, create a **Secret text** credential with the ID
   `openai-api-key`. For Anthropic, use `ANTHROPIC_API_KEY` and `--provider anthropic`.
2. Keep the `sh '''…'''` strings in **single quotes**. The key is then expanded by the shell, not
   interpolated by Groovy, so it never appears in the build log or the pipeline definition. agent-trace
   reads the key from the environment only and never stores it in a trace.

Model output is not deterministic, so treat this as a trend signal. Do not use it as a merge blocker.

The stage is skipped for pull requests (`not { changeRequest() }`): their code runs earlier in the
same workspace and could replace the binary or scripts this stage runs while the key is set.

### Multibranch and pull requests

The Jenkinsfile works unchanged in a Multibranch Pipeline. A red agent-trace stage is reported to
GitHub, GitLab or Bitbucket as a failed status check. Make that check *required* to block merges.

### Windows agents

The gate script needs a POSIX shell. Run it with Git Bash (`bash agent-trace-gate.sh …`) or on WSL.
Alternatively, call the three commands directly in a `bat`/`powershell` step and evaluate
`%ERRORLEVEL%` / `$LASTEXITCODE` the same way (0, 1, 2). There is a Windows release archive as well
(`x86_64-pc-windows-msvc`).

## 6. Try it locally first

```bash
mkdir -p /tmp/jenkins-try/traces
cp examples/ci/minimal-trace.jsonl /tmp/jenkins-try/traces/
sh examples/ci/agent-trace-gate.sh /tmp/jenkins-try/traces /tmp/jenkins-try/reports high
echo "exit code: $?"
#   AT-002 HIGH     blocked   …  Privileged tool request caused by lower-trust content  evidence: #2 → #3 → #4
#   findings at or above high — exit code 2
# exit code: 2
```

Jenkins does exactly the same thing in the gate stage.

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `agent-trace: command not found` | The binary is not on `PATH`. Set `PATH` as in the example `environment` block, or set `AGENT_TRACE=/path/to/agent-trace`. |
| `error: no *.jsonl traces in traces` | The agent tests wrote no traces, or wrote them somewhere else. Pass the correct directory as the first argument. |
| `rejected …: import failed at line N` | The trace is not valid JSONL or violates the schema (for example a dangling causal link). See [event-schema.md](event-schema.md). |
| `trace … already exists` | A fixed trace file was imported twice into a persistent database. See [shared database](#keeping-history-in-a-shared-database). |
| TLS handshake error against the database | TLS is enabled automatically for non-loopback hosts. The server needs a certificate trusted by the system roots. For a test database inside a private network, `sslmode=disable` (PostgreSQL) or `ssl-mode=disabled` (MySQL/MariaDB) turns TLS off. |
| Garbled characters in the log | Use `--no-color`; the gate script already does. Jenkins does not render ANSI colors without the AnsiColor plugin. |
| Build always red with `exit 1` instead of yellow | `sh` was called without `returnStatus: true`, so Jenkins treated every non-zero exit as a failure. |
