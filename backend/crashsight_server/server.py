"""REST API (v1) on the Python standard library.

NOTE: the original spec calls for FastAPI/SQLAlchemy/PostgreSQL. Those packages were
not installable in the build environment (no network), so this server uses
http.server + sqlite3. The Store/processing layers are framework-independent so a
FastAPI front end can be added later; see docs/architecture/overview.md.

Auth model: dashboard/admin endpoints need `Authorization: Bearer <CRASHSIGHT_ADMIN_TOKEN>`;
ingest and symbol upload need a project-scoped `X-API-Key`. There is no multi-user
account system.
"""
import hmac
import json
import os
import re
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from . import schema
from .service import ApiError, Store

MAX_SYMBOL_BYTES = 200 << 20
DASHBOARD_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "dashboard")


class RateLimiter:
    """Token bucket per key: `rate` requests/minute."""

    def __init__(self, rate):
        self.rate, self.buckets, self.lock = rate, {}, threading.Lock()

    def allow(self, key):
        t = time.monotonic()
        with self.lock:
            tokens, last = self.buckets.get(key, (float(self.rate), t))
            tokens = min(float(self.rate), tokens + (t - last) * self.rate / 60.0)
            if tokens < 1:
                self.buckets[key] = (tokens, t)
                return False
            self.buckets[key] = (tokens - 1, t)
            return True


def make_handler(store, admin_token, limiter):
    route = lambda pat: re.compile("^/api/v1" + pat + "$")
    R = {
        "health": re.compile(r"^/api/v1/health$"),
        "ready": re.compile(r"^/api/v1/ready$"),
        "projects": route(r"/projects"),
        "project_keys": route(r"/projects/(\d+)/keys"),
        "project_key": route(r"/projects/(\d+)/keys/(\d+)"),
        "project_symbols": route(r"/projects/(\d+)/symbols"),
        "project_purge": route(r"/projects/(\d+)/purge"),
        "reports": route(r"/reports"),
        "report": route(r"/reports/(\d+)"),
        "report_raw": route(r"/reports/(\d+)/raw"),
        "report_retry": route(r"/reports/(\d+)/retry"),
        "symbols": route(r"/symbols"),
        "groups": route(r"/groups"),
        "group": route(r"/groups/(\d+)"),
        "group_notes": route(r"/groups/(\d+)/notes"),
        "group_merge": route(r"/groups/(\d+)/merge"),
        "group_split": route(r"/groups/(\d+)/split"),
        "stats": route(r"/stats"),
        "audit": route(r"/audit"),
    }

    class Handler(BaseHTTPRequestHandler):
        server_version = "CrashSight/0.1"
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt, *args):  # structured, never logs headers/bodies/keys
            sys.stderr.write(json.dumps({"ts": time.time(), "client": self.client_address[0], "msg": fmt % args}) + "\n")

        # ---- plumbing
        def _send(self, status, payload, ctype="application/json"):
            body = payload if isinstance(payload, (bytes, bytearray)) else json.dumps(payload).encode()
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def _body(self, limit):
            try:
                n = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                raise ApiError(400, "bad_length", "invalid Content-Length")
            if n > limit:
                raise ApiError(413, "too_large", "body exceeds %d bytes" % limit)
            return self.rfile.read(n) if n else b""

        def _json(self):
            raw = self._body(1 << 20)
            try:
                v = json.loads(raw.decode() or "{}")
            except (ValueError, UnicodeDecodeError):
                raise ApiError(400, "malformed", "body is not valid JSON")
            if not isinstance(v, dict):
                raise ApiError(400, "malformed", "body must be a JSON object")
            return v

        def _admin(self):
            h = self.headers.get("Authorization", "")
            tok = h[7:] if h.startswith("Bearer ") else ""
            if not admin_token or not hmac.compare_digest(tok.encode(), admin_token.encode()):
                raise ApiError(401, "unauthorized", "admin token required")
            return "admin"

        def _key_project(self):
            found = store.project_for_key(self.headers.get("X-API-Key", ""))
            if not found:
                raise ApiError(401, "unauthorized", "valid project API key required")
            pid, kid = found
            if not limiter.allow(kid):
                raise ApiError(429, "rate_limited", "too many requests for this API key")
            return pid

        def _pid(self, q):
            try:
                return int(q.get("project_id", [""])[0])
            except ValueError:
                raise ApiError(400, "project_id", "project_id query parameter required")

        def _page(self, q):
            try:
                return int(q.get("limit", ["50"])[0]), int(q.get("offset", ["0"])[0])
            except ValueError:
                raise ApiError(400, "bad_page", "limit/offset must be integers")

        def _dispatch(self, method):
            u = urlparse(self.path)
            q = parse_qs(u.query)
            path = u.path
            if method == "GET" and path in ("/", "/index.html"):
                with open(os.path.join(DASHBOARD_DIR, "index.html"), "rb") as f:
                    return self._send(200, f.read(), "text/html; charset=utf-8")
            m = lambda k: R[k].match(path)
            if method == "GET" and m("health"):
                return self._send(200, {"status": "ok"})
            if method == "GET" and m("ready"):
                store.list_projects()
                return self._send(200, {"status": "ready"})
            # ---- API-key endpoints
            if method == "POST" and m("reports"):
                pid = self._key_project()
                return self._send(201, store.ingest(pid, self._body(schema.MAX_REPORT_BYTES + 1)))
            if method == "POST" and m("symbols"):
                pid = self._key_project()
                return self._send(201, store.register_symbols(
                    pid, self._body(MAX_SYMBOL_BYTES), q.get("module", ["unknown"])[0],
                    self.headers.get("X-Build-Id", ""), "api-key"))
            # ---- admin endpoints
            actor = self._admin()
            if m("projects"):
                if method == "GET":
                    return self._send(200, {"items": store.list_projects()})
                if method == "POST":
                    p, key = store.create_project(self._json().get("name"), actor)
                    return self._send(201, {"project": p, "api_key": key})
            if (x := m("project_keys")):
                pid = int(x.group(1))
                if method == "GET":
                    store.get_project(pid)
                    return self._send(200, {"items": store.list_keys(pid)})
                if method == "POST":
                    return self._send(201, store.create_key(pid, actor))
            if (x := m("project_key")) and method == "DELETE":
                store.revoke_key(int(x.group(1)), int(x.group(2)), actor)
                return self._send(200, {"revoked": True})
            if (x := m("project_symbols")) and method == "GET":
                return self._send(200, {"items": store.list_symbols(int(x.group(1)))})
            if (x := m("project_purge")) and method == "POST":
                days = self._json().get("older_than_days")
                if not isinstance(days, int) or days < 0:
                    raise ApiError(422, "bad_days", "older_than_days must be a non-negative integer")
                return self._send(200, {"deleted": store.purge_older_than(int(x.group(1)), days, actor)})
            if m("reports") and method == "GET":
                pid, (lim, off) = self._pid(q), self._page(q)
                gid = q.get("group_id", [None])[0]
                return self._send(200, store.list_reports(pid, int(gid) if gid else None, q.get("status", [None])[0],
                                                          q.get("kind", [None])[0], lim, off))
            if (x := m("report")) and method == "GET":
                return self._send(200, store.get_report(self._pid(q), int(x.group(1))))
            if (x := m("report_raw")) and method == "GET":
                return self._send(200, store.raw_artifact(self._pid(q), int(x.group(1))))
            if (x := m("report_retry")) and method == "POST":
                return self._send(200, store.retry(self._pid(q), int(x.group(1)), actor))
            if m("groups") and method == "GET":
                pid, (lim, off) = self._pid(q), self._page(q)
                return self._send(200, store.list_groups(pid, q.get("status", [None])[0], q.get("q", [None])[0],
                                                         q.get("sort", ["last_seen"])[0], lim, off))
            if (x := m("group")):
                gid = int(x.group(1))
                if method == "GET":
                    return self._send(200, store.get_group(self._pid(q), gid))
                if method == "PATCH":
                    return self._send(200, store.update_group(self._pid(q), gid, self._json(), actor))
            if (x := m("group_notes")) and method == "POST":
                return self._send(201, store.add_note(self._pid(q), int(x.group(1)), self._json(), actor))
            if (x := m("group_merge")) and method == "POST":
                into = self._json().get("into")
                if not isinstance(into, int):
                    raise ApiError(422, "bad_target", "'into' must be a group id")
                return self._send(200, store.merge_groups(self._pid(q), int(x.group(1)), into, actor))
            if (x := m("group_split")) and method == "POST":
                rid = self._json().get("report_id")
                if not isinstance(rid, int):
                    raise ApiError(422, "bad_report", "'report_id' must be an integer")
                return self._send(201, store.split_report(self._pid(q), int(x.group(1)), rid, actor))
            if m("stats") and method == "GET":
                days = int(q.get("days", ["30"])[0])
                return self._send(200, store.stats(self._pid(q), max(1, min(days, 365))))
            if m("audit") and method == "GET":
                return self._send(200, {"items": store.audit_log(self._pid(q))})
            raise ApiError(404, "not_found", "no such endpoint")

        def _handle(self, method):
            try:
                self._dispatch(method)
            except ApiError as e:
                self._send(e.status, {"error": {"code": e.code, "message": e.message}})
            except Exception as e:  # unexpected: log type only, return generic error
                sys.stderr.write(json.dumps({"error": type(e).__name__}) + "\n")
                self._send(500, {"error": {"code": "internal", "message": "internal error"}})

        def do_GET(self): self._handle("GET")
        def do_POST(self): self._handle("POST")
        def do_PATCH(self): self._handle("PATCH")
        def do_DELETE(self): self._handle("DELETE")

    return Handler


def create_server(data_dir, admin_token, host="127.0.0.1", port=8000, rate_per_minute=120):
    if not admin_token or len(admin_token) < 16:
        raise SystemExit("CRASHSIGHT_ADMIN_TOKEN must be set to at least 16 characters")
    store = Store(data_dir)
    srv = ThreadingHTTPServer((host, port), make_handler(store, admin_token, RateLimiter(rate_per_minute)))
    srv.store = store
    return srv


def main():
    srv = create_server(os.environ.get("CRASHSIGHT_DATA_DIR", "./data"), os.environ.get("CRASHSIGHT_ADMIN_TOKEN", ""),
                        os.environ.get("CRASHSIGHT_HOST", "127.0.0.1"), int(os.environ.get("CRASHSIGHT_PORT", "8000")))
    print("CrashSight listening on http://%s:%d" % srv.server_address, flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
