#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [[ ! -x ./jada ]]; then
    echo "jada binary not found. Build it before running the smoke test." >&2
    exit 1
fi

MANAGED_OUTPUT="$(printf 'node.start tests/config.smoke.json\nnode.status\nput alpha bravo ttl=30\nget alpha\ngroup.put dns a1=1.2.3.4 a2=1.2.3.5 infinite=true\ngroup.get dns\nnode.stop\nnode.status\nexit\n' | ./jada)"

printf '%s\n' "$MANAGED_OUTPUT"
grep -q 'Managed local node started' <<< "$MANAGED_OUTPUT"
grep -q 'Managed local node: running' <<< "$MANAGED_OUTPUT"
grep -q '"value":"bravo"' <<< "$MANAGED_OUTPUT"
grep -q '"value":"1.2.3.4"' <<< "$MANAGED_OUTPUT"
grep -q '"value":"1.2.3.5"' <<< "$MANAGED_OUTPUT"
grep -q 'Managed local node stopped' <<< "$MANAGED_OUTPUT"
grep -q 'Managed local node: stopped' <<< "$MANAGED_OUTPUT"

./jada --config tests/config.smoke.json > tests/node.log 2>&1 &
NODE_PID=$!
cleanup(){
    kill "$NODE_PID" 2>/dev/null || true
    wait "$NODE_PID" 2>/dev/null || true
}
trap cleanup EXIT

READY=0
for _ in $(seq 1 100); do
    if printf 'get readiness\nexit\n' | ./jada --cli 127.0.0.1:28080 2>/dev/null | grep -q '"ok"'; then
        READY=1
        break
    fi
    sleep 0.05
done

if [[ "$READY" -ne 1 ]]; then
    echo "standalone node did not become reachable" >&2
    exit 1
fi

ATTACHED_OUTPUT="$(printf 'put external attached ttl=30\nget external\nexit\n' | ./jada --cli 127.0.0.1:28080)"
printf '%s\n' "$ATTACHED_OUTPUT"
grep -q '"value":"attached"' <<< "$ATTACHED_OUTPUT"

cleanup
trap - EXIT

echo "Jada smoke test passed."
