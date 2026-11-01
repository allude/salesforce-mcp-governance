#!/usr/bin/env bash
# Live end-to-end smoke test (run via `npm run test:e2e`):
#   1. builds the backend (dist/) and the Next.js portal (npm run build)
#   2. boots Express (:3001) and Next.js (:3000) in the background against a throwaway SQLite DB
#   3. waits up to 20s for both ports, then runs scripts/smoke-checks.mjs through the :3000 proxy
#   4. always stops both servers and deletes the temp DB (trap on EXIT)
set -euo pipefail
set -m # job control: each background server gets its own process group, so cleanup kills workers too

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

BACKEND_PORT="${SMOKE_BACKEND_PORT:-3001}"
PORTAL_PORT="${SMOKE_PORTAL_PORT:-3000}"
BOOT_TIMEOUT_SECONDS="${SMOKE_BOOT_TIMEOUT:-20}"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/sf-mcp-smoke.XXXXXX")"
PIDS=()

cleanup() {
  # Explicit status for signals, so an interrupted run never counts as a pass.
  local status="${1:-$?}"
  trap - EXIT INT TERM
  for pid in "${PIDS[@]:-}"; do
    [ -n "$pid" ] || continue
    kill -TERM -- "-$pid" 2>/dev/null || kill -TERM "$pid" 2>/dev/null || true
  done
  for pid in "${PIDS[@]:-}"; do
    [ -n "$pid" ] || continue
    wait "$pid" 2>/dev/null || true
  done
  if [ "$status" -ne 0 ]; then
    for log in "$TMP_DIR"/*.log; do
      [ -f "$log" ] || continue
      echo "----- $(basename "$log") (last 40 lines) -----"
      tail -n 40 "$log"
    done
  fi
  rm -rf "$TMP_DIR"
  exit "$status"
}
trap 'cleanup' EXIT
trap 'cleanup 130' INT
trap 'cleanup 143' TERM

port_in_use() {
  curl -s -o /dev/null --max-time 1 "http://127.0.0.1:$1/" 2>/dev/null
}

for port in "$BACKEND_PORT" "$PORTAL_PORT"; do
  if port_in_use "$port"; then
    echo "✖ Port $port is already in use. Stop the running dev server (or set SMOKE_BACKEND_PORT / SMOKE_PORTAL_PORT) and retry."
    exit 1
  fi
done

export NEXT_TELEMETRY_DISABLED=1
export MCP_BACKEND_URL="http://localhost:${BACKEND_PORT}"
export BASE_URL="http://localhost:${PORTAL_PORT}"

echo "▶ [1/4] npm run build (backend compile + Next.js production build)"
npm run build > "$TMP_DIR/build.log" 2>&1 || { echo "✖ npm run build failed"; tail -n 60 "$TMP_DIR/build.log"; exit 1; }
echo "✔ build succeeded"

echo "▶ [2/4] starting Express :${BACKEND_PORT} and Next.js :${PORTAL_PORT} (DB: $TMP_DIR/smoke.sqlite)"
PORT="$BACKEND_PORT" DB_PATH="$TMP_DIR/smoke.sqlite" NODE_ENV=test \
  ADMIN_BOOTSTRAP_USERNAME=admin ADMIN_BOOTSTRAP_PASSWORD=admin123 \
  node dist/index.js > "$TMP_DIR/backend.log" 2>&1 &
PIDS+=("$!")
node_modules/.bin/next start --port "$PORTAL_PORT" > "$TMP_DIR/portal.log" 2>&1 &
PIDS+=("$!")

echo "▶ [3/4] waiting up to ${BOOT_TIMEOUT_SECONDS}s for both servers"
deadline=$((SECONDS + BOOT_TIMEOUT_SECONDS))
until curl -s -o /dev/null --max-time 1 "http://127.0.0.1:${BACKEND_PORT}/healthz" \
  && curl -s -o /dev/null --max-time 1 "http://127.0.0.1:${PORTAL_PORT}/"; do
  if [ "$SECONDS" -ge "$deadline" ]; then
    echo "✖ servers did not start listening within ${BOOT_TIMEOUT_SECONDS}s"
    exit 1
  fi
  for pid in "${PIDS[@]}"; do
    kill -0 "$pid" 2>/dev/null || { echo "✖ a server process exited during startup"; exit 1; }
  done
  sleep 0.5
done
echo "✔ both servers are listening"

echo "▶ [4/4] running live checks through the Next.js proxy"
SMOKE_PORTAL_URL="http://127.0.0.1:${PORTAL_PORT}" SMOKE_BACKEND_URL="http://127.0.0.1:${BACKEND_PORT}" \
  SMOKE_PUBLIC_URL="$BASE_URL" node scripts/smoke-checks.mjs
