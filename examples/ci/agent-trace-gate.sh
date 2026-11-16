#!/bin/sh
# agent-trace CI gate: import every trace with a threshold, export redacted evidence.
#
# Usage: agent-trace-gate.sh [TRACE_DIR] [REPORT_DIR] [THRESHOLD]
#   TRACE_DIR   directory with *.jsonl traces          (default: traces)
#   REPORT_DIR  where redacted traces (JSONL) and findings (.txt) go (default: reports)
#   THRESHOLD   low | medium | high | critical          (default: high)
#
# Exit codes (same contract as `agent-trace analyze` / `import --fail-on`):
#   0  no finding at or above the threshold
#   1  error (no traces, invalid trace, database problem, ...)
#   2  at least one finding at or above the threshold
#
# Uses $AGENT_TRACE_DATA_DIR / $AGENT_TRACE_DATABASE_URL if set; otherwise a fresh
# temporary data directory, so runs never see each other's traces.

set -u

TRACE_DIR=${1:-traces}
REPORT_DIR=${2:-reports}
THRESHOLD=${3:-high}
AGENT_TRACE=${AGENT_TRACE:-agent-trace}

if [ -z "${AGENT_TRACE_DATA_DIR:-}" ] && [ -z "${AGENT_TRACE_DATABASE_URL:-}" ]; then
    AGENT_TRACE_DATA_DIR=$(mktemp -d "${TMPDIR:-/tmp}/agent-trace.XXXXXX") || exit 1
    export AGENT_TRACE_DATA_DIR
fi

mkdir -p "$REPORT_DIR" || exit 1

found=0
result=0
for f in "$TRACE_DIR"/*.jsonl; do
    [ -e "$f" ] || continue
    found=1
    name=$(basename "$f" .jsonl)
    echo "== $name"

    # The verdict comes from the validated import itself (`import --fail-on`), not from a
    # later read of the database, which another writer of a shared database could change.
    "$AGENT_TRACE" --no-color import --input "$f" --fail-on "$THRESHOLD" >"$REPORT_DIR/$name.txt" 2>&1
    code=$?
    cat "$REPORT_DIR/$name.txt"
    case $code in
        0) ;;
        2) [ "$result" -eq 1 ] || result=2 ;;
        *)
            echo "error: could not import $f" >&2
            result=1
            continue
            ;;
    esac

    # Evidence export addresses the trace by the id `import` reported, never by `--latest`.
    id=$(sed -n 's/^imported trace \([0-9a-f-]*\).*/\1/p' "$REPORT_DIR/$name.txt")
    if [ -z "$id" ]; then
        echo "error: no trace id in import output for $f" >&2
        result=1
        continue
    fi
    "$AGENT_TRACE" --no-color export "$id" --format jsonl --output "$REPORT_DIR/$name.jsonl" || result=1
done

if [ "$found" -eq 0 ]; then
    echo "error: no *.jsonl traces in $TRACE_DIR" >&2
    exit 1
fi
exit "$result"
