#!/usr/bin/env bash
# End-to-end demo / test (Linux). Builds the sample, crashes it in a controlled way,
# starts the backend, uploads symbols, ingests reports and verifies grouping.
set -euo pipefail
cd "$(dirname "$0")/.."
export CRASHSIGHT_ADMIN_TOKEN="${CRASHSIGHT_ADMIN_TOKEN:-demo-admin-token-change-me-123}"
PORT="${PORT:-$(python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1])')}"; URL="http://127.0.0.1:$PORT"
WORK="$(mktemp -d)"; trap 'kill $SRV 2>/dev/null || true; rm -rf "$WORK"' EXIT
pass() { echo "PASS: $*"; }; fail() { echo "FAIL: $*"; exit 1; }

scripts/build_native.sh debug >/dev/null && pass "native build"
mkdir -p "$WORK/r"
./build/basic_cpp_app --out="$WORK/r" >/dev/null && pass "normal run does not crash"
for i in 1 2; do ./build/basic_cpp_app --out="$WORK/r" --crash=null-deref >/dev/null 2>&1 || true; done
./build/basic_cpp_app --out="$WORK/r" --crash=abort >/dev/null 2>&1 || true
./build/basic_c_app --out="$WORK/r" >/dev/null     # next start finalizes raw crash records
FATAL=$(grep -l '"kind": "fatal"' "$WORK"/r/*.json | wc -l)
[ "$FATAL" -eq 3 ] && pass "3 local crash artifacts created" || fail "expected 3 fatal artifacts, got $FATAL"

PYTHONPATH=backend CRASHSIGHT_DATA_DIR="$WORK/data" CRASHSIGHT_PORT=$PORT python3 -m crashsight_server.server >"$WORK/server.out" 2>"$WORK/server.log" & SRV=$!
for _ in $(seq 50); do curl -sf "$URL/api/v1/health" >/dev/null && break; sleep 0.1; done
kill -0 "$SRV" 2>/dev/null || { cat "$WORK/server.log"; fail "backend process exited (port in use?)"; }
curl -sf "$URL/api/v1/health" >/dev/null && pass "backend healthy"

AUTH="Authorization: Bearer $CRASHSIGHT_ADMIN_TOKEN"
RESP=$(curl -sf -H "$AUTH" -X POST -d '{"name":"demo"}' "$URL/api/v1/projects")
KEY=$(python3 -c "import json,sys;print(json.loads(sys.argv[1])['api_key']['key'])" "$RESP")
PID=$(python3 -c "import json,sys;print(json.loads(sys.argv[1])['project']['id'])" "$RESP")
python3 scripts/cs_client.py upload-symbols --url "$URL" --key "$KEY" --binary build/basic_cpp_app >/dev/null && pass "symbols registered"
for f in $(grep -l '"kind": "fatal"' "$WORK"/r/*.json); do
  python3 scripts/cs_client.py submit --url "$URL" --key "$KEY" "$f" >/dev/null || fail "submit $f"
done
pass "3 reports ingested"

python3 - "$URL" "$CRASHSIGHT_ADMIN_TOKEN" "$PID" <<'PY'
import json, sys, urllib.request
url, tok, pid = sys.argv[1:]
def get(p):
    r = urllib.request.Request(url + "/api/v1" + p, headers={"Authorization": "Bearer " + tok})
    return json.load(urllib.request.urlopen(r))
g = get("/groups?project_id=%s&sort=occurrences" % pid)
counts = sorted(x["occurrences"] for x in g["items"])
assert counts == [1, 2], "expected groups with 2 and 1 occurrences, got %s" % counts
print("PASS: equivalent crashes grouped (2) and unrelated crash separate (1)")
top = g["items"][0]
rep = get("/reports?project_id=%s&group_id=%d" % (pid, top["id"]))["items"][0]
full = get("/reports/%d?project_id=%s" % (rep["id"], pid))
fns = [f.get("function") for f in full["frames"] if f["status"] == "symbolicated"]
assert any("level3" in (f or "") for f in fns), fns
print("PASS: symbolicated stack:", " <- ".join(f for f in fns if f)[:140])
s = get("/stats?project_id=%s&days=3650" % pid)
assert s["total_fatal_reports"] == 3 and s["unique_groups"] == 2
print("PASS: stats derived from stored reports:", s["total_fatal_reports"], "reports,", s["unique_groups"], "groups")
PY
PAGE=$(curl -sf "$URL/") || fail "dashboard request failed"
case "$PAGE" in *"<title>CrashSight</title>"*) pass "dashboard served at /";; *) fail "dashboard content unexpected";; esac
echo "E2E COMPLETE"
