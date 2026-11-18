"""Persistence + processing pipeline (SQLite). All project isolation is enforced
here: every query that touches project data is scoped by project_id."""
import hashlib
import json
import os
import re
import secrets
import sqlite3
import threading
import time

from . import grouping, schema
from .symbolicate import SymbolError, SymbolStore

STATUSES = ("new", "investigating", "confirmed", "resolved", "reopened", "ignored")
SEVERITIES = ("low", "medium", "high", "critical")
_SENSITIVE = re.compile(r"(token|secret|passw|key|auth|cookie|credential)", re.I)

DDL = """
CREATE TABLE IF NOT EXISTS projects(
  id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE, created_at TEXT NOT NULL, archived INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS api_keys(
  id INTEGER PRIMARY KEY, project_id INTEGER NOT NULL REFERENCES projects(id),
  key_hash TEXT NOT NULL UNIQUE, prefix TEXT NOT NULL, created_at TEXT NOT NULL, revoked_at TEXT);
CREATE TABLE IF NOT EXISTS symbol_files(
  id INTEGER PRIMARY KEY, project_id INTEGER NOT NULL REFERENCES projects(id),
  build_id TEXT NOT NULL, module_name TEXT NOT NULL, has_debug_info INTEGER NOT NULL,
  size INTEGER NOT NULL, created_at TEXT NOT NULL, UNIQUE(project_id, build_id));
CREATE TABLE IF NOT EXISTS crash_groups(
  id INTEGER PRIMARY KEY, project_id INTEGER NOT NULL REFERENCES projects(id),
  signature TEXT NOT NULL, signature_version INTEGER NOT NULL, title TEXT NOT NULL,
  crash_type TEXT NOT NULL, status TEXT NOT NULL CHECK(status IN ('new','investigating','confirmed','resolved','reopened','ignored')),
  severity TEXT NOT NULL CHECK(severity IN ('low','medium','high','critical')),
  assignee TEXT, explanation TEXT NOT NULL, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
  UNIQUE(project_id, signature));
CREATE TABLE IF NOT EXISTS crash_reports(
  id INTEGER PRIMARY KEY, project_id INTEGER NOT NULL REFERENCES projects(id),
  report_id TEXT NOT NULL, group_id INTEGER REFERENCES crash_groups(id),
  kind TEXT NOT NULL, crash_type TEXT NOT NULL, app_name TEXT NOT NULL, app_version TEXT NOT NULL,
  build_id TEXT NOT NULL, environment TEXT NOT NULL, occurred_at TEXT NOT NULL, received_at TEXT NOT NULL,
  processing_status TEXT NOT NULL, processing_error TEXT, symbolication_status TEXT NOT NULL,
  signature TEXT, frames_json TEXT NOT NULL, detail_json TEXT NOT NULL, artifact_path TEXT NOT NULL,
  UNIQUE(project_id, report_id));
CREATE INDEX IF NOT EXISTS idx_reports_group ON crash_reports(group_id);
CREATE INDEX IF NOT EXISTS idx_reports_project_time ON crash_reports(project_id, occurred_at);
CREATE INDEX IF NOT EXISTS idx_groups_project_status ON crash_groups(project_id, status);
CREATE TABLE IF NOT EXISTS notes(
  id INTEGER PRIMARY KEY, group_id INTEGER NOT NULL REFERENCES crash_groups(id),
  author TEXT NOT NULL, body TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS audit_events(
  id INTEGER PRIMARY KEY, project_id INTEGER, actor TEXT NOT NULL, action TEXT NOT NULL,
  target TEXT NOT NULL, detail TEXT NOT NULL, created_at TEXT NOT NULL);
"""


class ApiError(Exception):
    def __init__(self, status, code, message):
        super().__init__(message)
        self.status, self.code, self.message = status, code, message


def now():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def mask_context(ctx):
    return {k: ("***" if _SENSITIVE.search(k) else v) for k, v in ctx.items()}


class Store:
    def __init__(self, data_dir):
        self.data_dir = os.path.abspath(data_dir)
        os.makedirs(os.path.join(self.data_dir, "artifacts"), exist_ok=True)
        self.db = sqlite3.connect(os.path.join(self.data_dir, "crashsight.db"), check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA foreign_keys=ON")
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.executescript(DDL)
        self.lock = threading.RLock()
        self._symbols = {}

    # ---- helpers
    def _q(self, sql, args=()):
        with self.lock:
            return [dict(r) for r in self.db.execute(sql, args).fetchall()]

    def _one(self, sql, args=()):
        rows = self._q(sql, args)
        return rows[0] if rows else None

    def _exec(self, sql, args=()):
        with self.lock:
            cur = self.db.execute(sql, args)
            self.db.commit()
            return cur.lastrowid

    def audit(self, project_id, actor, action, target, detail=""):
        self._exec("INSERT INTO audit_events(project_id,actor,action,target,detail,created_at) VALUES(?,?,?,?,?,?)",
                   (project_id, actor, action, target, detail, now()))

    def symbols(self, project_id):
        if project_id not in self._symbols:
            self._symbols[project_id] = SymbolStore(os.path.join(self.data_dir, "symbols", str(project_id)))
        return self._symbols[project_id]

    # ---- projects & keys
    def create_project(self, name, actor):
        if not isinstance(name, str) or not re.fullmatch(r"[\w .-]{1,64}", name):
            raise ApiError(400, "invalid_name", "project name must be 1-64 chars of letters, digits, space, . _ -")
        try:
            pid = self._exec("INSERT INTO projects(name,created_at) VALUES(?,?)", (name, now()))
        except sqlite3.IntegrityError:
            raise ApiError(409, "exists", "project name already exists")
        self.audit(pid, actor, "project.create", name)
        key = self.create_key(pid, actor)
        return self.get_project(pid), key

    def get_project(self, pid):
        p = self._one("SELECT id,name,created_at,archived FROM projects WHERE id=?", (pid,))
        if not p:
            raise ApiError(404, "not_found", "project not found")
        return p

    def list_projects(self):
        return self._q("SELECT id,name,created_at,archived FROM projects ORDER BY id")

    def create_key(self, pid, actor):
        self.get_project(pid)
        raw = "cs_" + secrets.token_urlsafe(32)
        h = hashlib.sha256(raw.encode()).hexdigest()
        kid = self._exec("INSERT INTO api_keys(project_id,key_hash,prefix,created_at) VALUES(?,?,?,?)",
                         (pid, h, raw[:8], now()))
        self.audit(pid, actor, "key.create", "key:%d" % kid)
        return {"id": kid, "key": raw, "note": "shown once; only a hash is stored"}

    def revoke_key(self, pid, kid, actor):
        row = self._one("SELECT id FROM api_keys WHERE id=? AND project_id=? AND revoked_at IS NULL", (kid, pid))
        if not row:
            raise ApiError(404, "not_found", "active key not found")
        self._exec("UPDATE api_keys SET revoked_at=? WHERE id=?", (now(), kid))
        self.audit(pid, actor, "key.revoke", "key:%d" % kid)

    def list_keys(self, pid):
        return self._q("SELECT id,prefix,created_at,revoked_at FROM api_keys WHERE project_id=? ORDER BY id", (pid,))

    def project_for_key(self, raw):
        if not raw:
            return None
        h = hashlib.sha256(raw.encode()).hexdigest()
        row = self._one("SELECT k.id kid, k.project_id FROM api_keys k JOIN projects p ON p.id=k.project_id "
                        "WHERE k.key_hash=? AND k.revoked_at IS NULL AND p.archived=0", (h,))
        return (row["project_id"], row["kid"]) if row else None

    # ---- symbols
    def register_symbols(self, pid, data, module_name, claimed_build_id, actor):
        try:
            build_id, dbg = self.symbols(pid).register(data, claimed_build_id or None)
        except SymbolError as e:
            raise ApiError(422, "bad_symbols", str(e))
        with self.lock:
            self.db.execute("INSERT OR REPLACE INTO symbol_files(project_id,build_id,module_name,has_debug_info,size,created_at) "
                            "VALUES(?,?,?,?,?,?)", (pid, build_id, module_name[:128] or "unknown", int(dbg), len(data), now()))
            self.db.commit()
        self.audit(pid, actor, "symbols.register", build_id, module_name[:128])
        return {"build_id": build_id, "has_debug_info": dbg, "size": len(data)}

    def list_symbols(self, pid):
        return self._q("SELECT build_id,module_name,has_debug_info,size,created_at FROM symbol_files WHERE project_id=? ORDER BY id DESC", (pid,))

    # ---- ingestion & processing
    def ingest(self, pid, raw_bytes, actor="api-key"):
        if len(raw_bytes) > schema.MAX_REPORT_BYTES:
            raise ApiError(413, "too_large", "report exceeds %d bytes" % schema.MAX_REPORT_BYTES)
        try:
            doc = json.loads(raw_bytes.decode("utf-8"))
            rep = schema.validate_report(doc)
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise ApiError(400, "malformed", "body is not valid UTF-8 JSON")
        except schema.ValidationError as e:
            raise ApiError(422, "invalid_report", str(e))
        if self._one("SELECT id FROM crash_reports WHERE project_id=? AND report_id=?", (pid, rep["report_id"])):
            raise ApiError(409, "duplicate", "report_id already ingested")
        art_dir = os.path.join(self.data_dir, "artifacts", str(pid))
        os.makedirs(art_dir, exist_ok=True)
        art = os.path.join(art_dir, hashlib.sha256(rep["report_id"].encode()).hexdigest() + ".json")
        with open(art, "wb") as f:
            f.write(raw_bytes)
        rid = self._exec(
            "INSERT INTO crash_reports(project_id,report_id,kind,crash_type,app_name,app_version,build_id,environment,"
            "occurred_at,received_at,processing_status,symbolication_status,frames_json,detail_json,artifact_path) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (pid, rep["report_id"], rep["kind"], rep["crash_type"], rep["application_name"], rep["application_version"],
             rep["build_id"], rep["environment"], rep["timestamp_utc"] or now(), now(), "pending", "not_applicable",
             "[]", json.dumps(rep), art))
        self.process(rid)
        return self.get_report(pid, rid)

    def process(self, rid):
        """Deterministic pipeline: symbolicate -> signature -> group -> stats. Records errors."""
        row = self._one("SELECT * FROM crash_reports WHERE id=?", (rid,))
        try:
            rep = json.loads(row["detail_json"])
            pid = row["project_id"]
            frames, sym_status = self._symbolicate(pid, rep)
            group_id, sig = None, None
            if rep["kind"] == "fatal":
                sig, explanation, title = grouping.compute_signature(rep["crash_type"], frames)
                group_id = self._attach_group(pid, row, sig, explanation, title, rep["crash_type"])
            old_group = row["group_id"]
            with self.lock:
                self.db.execute("UPDATE crash_reports SET frames_json=?, symbolication_status=?, signature=?, group_id=?, "
                                "processing_status='processed', processing_error=NULL WHERE id=?",
                                (json.dumps(frames), sym_status, sig, group_id, rid))
                self.db.commit()
            if old_group and old_group != group_id:
                self.audit(pid, "system", "report.regroup", "report:%d" % rid, "group %s -> %s" % (old_group, group_id))
        except Exception as e:  # recorded, never swallowed silently
            self._exec("UPDATE crash_reports SET processing_status='failed', processing_error=? WHERE id=?", (str(e)[:500], rid))

    def _symbolicate(self, pid, rep):
        if rep["kind"] != "fatal":
            return [], "not_applicable"
        build_ids = {m["name"]: m["build_id"] for m in rep["modules"]}
        store = self.symbols(pid)
        out, resolved = [], 0
        for i, f in enumerate(rep["frames"]):
            res = store.resolve(build_ids.get(f["module"], ""), f["module_offset"], i > 0)
            frame = {"index": i, "address": "0x%x" % f["address"], "module": f["module"],
                     "module_offset": f["module_offset"], "build_id": build_ids.get(f["module"], "")}
            frame.update(res)
            resolved += res["status"] == "symbolicated"
            out.append(frame)
        if not out:
            return out, "no_frames"
        return out, ("symbolicated" if resolved == len(out) else "partial" if resolved else "unresolved")

    def _attach_group(self, pid, row, sig, explanation, title, crash_type):
        ts = row["occurred_at"]
        with self.lock:
            g = self.db.execute("SELECT * FROM crash_groups WHERE project_id=? AND signature=?", (pid, sig)).fetchone()
            if g is None:
                cur = self.db.execute(
                    "INSERT INTO crash_groups(project_id,signature,signature_version,title,crash_type,status,severity,explanation,first_seen,last_seen) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?)",
                    (pid, sig, grouping.SIGNATURE_VERSION, title, crash_type, "new", "medium", explanation, ts, ts))
                self.db.commit()
                return cur.lastrowid
            g = dict(g)
            sets, args = ["last_seen=MAX(last_seen,?)", "first_seen=MIN(first_seen,?)", "title=?", "explanation=?"], [ts, ts, title, explanation]
            if g["status"] == "resolved":
                sets.append("status='reopened'")
            self.db.execute("UPDATE crash_groups SET %s WHERE id=?" % ",".join(sets), args + [g["id"]])
            self.db.commit()
        if g["status"] == "resolved":
            self.audit(pid, "system", "group.reopen", "group:%d" % g["id"], "new report after resolve (regression)")
        return g["id"]

    def retry(self, pid, rid, actor):
        row = self._one("SELECT id FROM crash_reports WHERE id=? AND project_id=?", (rid, pid))
        if not row:
            raise ApiError(404, "not_found", "report not found")
        self.process(rid)
        self.audit(pid, actor, "report.retry", "report:%d" % rid)
        return self.get_report(pid, rid)

    # ---- reads
    def _report_view(self, r, full):
        detail = json.loads(r["detail_json"])
        v = {k: r[k] for k in ("id", "project_id", "report_id", "group_id", "kind", "crash_type", "app_name", "app_version",
                               "build_id", "environment", "occurred_at", "received_at", "processing_status",
                               "processing_error", "symbolication_status")}
        if full:
            v["frames"] = json.loads(r["frames_json"])
            v["context"] = mask_context(detail.get("context", {}))
            v["modules"] = detail.get("modules", [])
            v["os"], v["architecture"] = detail.get("os"), detail.get("architecture")
            v["process_id"], v["thread_id"] = detail.get("process_id"), detail.get("thread_id")
            v["fault_address"] = "0x%x" % detail.get("fault_address", 0)
            v["message"] = detail.get("message")
            v["capture_method"], v["capture_limitations"] = detail.get("capture_method"), detail.get("capture_limitations")
        return v

    def get_report(self, pid, rid):
        r = self._one("SELECT * FROM crash_reports WHERE id=? AND project_id=?", (rid, pid))
        if not r:
            raise ApiError(404, "not_found", "report not found")
        return self._report_view(r, True)

    def raw_artifact(self, pid, rid):
        r = self._one("SELECT artifact_path FROM crash_reports WHERE id=? AND project_id=?", (rid, pid))
        if not r:
            raise ApiError(404, "not_found", "report not found")
        with open(r["artifact_path"], "rb") as f:
            return f.read()

    def list_reports(self, pid, group_id=None, status=None, kind=None, limit=50, offset=0):
        where, args = ["project_id=?"], [pid]
        if group_id:
            where.append("group_id=?"); args.append(group_id)
        if status:
            where.append("processing_status=?"); args.append(status)
        if kind:
            where.append("kind=?"); args.append(kind)
        w = " AND ".join(where)
        total = self._one("SELECT COUNT(*) c FROM crash_reports WHERE " + w, args)["c"]
        rows = self._q("SELECT * FROM crash_reports WHERE %s ORDER BY occurred_at DESC, id DESC LIMIT ? OFFSET ?" % w,
                       args + [min(limit, 200), offset])
        return {"total": total, "items": [self._report_view(r, False) for r in rows]}

    def _group_view(self, g):
        s = self._one("SELECT COUNT(*) c, COUNT(DISTINCT app_version) v FROM crash_reports WHERE group_id=?", (g["id"],))
        g["occurrences"] = s["c"]
        g["affected_versions"] = [r["app_version"] for r in self._q(
            "SELECT DISTINCT app_version FROM crash_reports WHERE group_id=? ORDER BY app_version", (g["id"],))]
        return g

    def list_groups(self, pid, status=None, q=None, sort="last_seen", limit=50, offset=0):
        where, args = ["project_id=?"], [pid]
        if status:
            where.append("status=?"); args.append(status)
        if q:
            where.append("(title LIKE ? ESCAPE '\\' OR crash_type LIKE ? ESCAPE '\\')")
            like = "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
            args += [like, like]
        order = {"last_seen": "last_seen DESC", "first_seen": "first_seen DESC", "severity": "severity DESC, last_seen DESC",
                 "occurrences": "(SELECT COUNT(*) FROM crash_reports r WHERE r.group_id=crash_groups.id) DESC"}.get(sort)
        if order is None:
            raise ApiError(400, "bad_sort", "sort must be last_seen, first_seen, severity or occurrences")
        w = " AND ".join(where)
        total = self._one("SELECT COUNT(*) c FROM crash_groups WHERE " + w, args)["c"]
        rows = self._q("SELECT * FROM crash_groups WHERE %s ORDER BY %s LIMIT ? OFFSET ?" % (w, order), args + [min(limit, 200), offset])
        return {"total": total, "items": [self._group_view(g) for g in rows]}

    def get_group(self, pid, gid):
        g = self._one("SELECT * FROM crash_groups WHERE id=? AND project_id=?", (gid, pid))
        if not g:
            raise ApiError(404, "not_found", "group not found")
        g = self._group_view(g)
        g["notes"] = self._q("SELECT author,body,created_at FROM notes WHERE group_id=? ORDER BY id", (gid,))
        g["history"] = self._q("SELECT actor,action,detail,created_at FROM audit_events WHERE target=? ORDER BY id", ("group:%d" % gid,))
        return g

    # ---- investigation workflow
    def update_group(self, pid, gid, body, actor):
        g = self.get_group(pid, gid)
        sets, args, changes = [], [], []
        if "status" in body:
            if body["status"] not in STATUSES:
                raise ApiError(422, "bad_status", "status must be one of %s" % ", ".join(STATUSES))
            sets.append("status=?"); args.append(body["status"]); changes.append("status %s->%s" % (g["status"], body["status"]))
        if "severity" in body:
            if body["severity"] not in SEVERITIES:
                raise ApiError(422, "bad_severity", "severity must be one of %s" % ", ".join(SEVERITIES))
            sets.append("severity=?"); args.append(body["severity"]); changes.append("severity %s->%s" % (g["severity"], body["severity"]))
        if "assignee" in body:
            a = body["assignee"]
            if a is not None and (not isinstance(a, str) or len(a) > 64):
                raise ApiError(422, "bad_assignee", "assignee must be a string up to 64 chars or null")
            sets.append("assignee=?"); args.append(a); changes.append("assignee %s->%s" % (g["assignee"], a))
        if not sets:
            raise ApiError(422, "empty", "nothing to update")
        self._exec("UPDATE crash_groups SET %s WHERE id=?" % ",".join(sets), args + [gid])
        self.audit(pid, actor, "group.update", "group:%d" % gid, "; ".join(changes))
        return self.get_group(pid, gid)

    def add_note(self, pid, gid, body, actor):
        self.get_group(pid, gid)
        text = body.get("body")
        if not isinstance(text, str) or not text.strip() or len(text) > 4000:
            raise ApiError(422, "bad_note", "note body must be 1-4000 characters")
        self._exec("INSERT INTO notes(group_id,author,body,created_at) VALUES(?,?,?,?)", (gid, actor, text.strip(), now()))
        self.audit(pid, actor, "group.note", "group:%d" % gid)
        return self.get_group(pid, gid)

    def merge_groups(self, pid, src, dst, actor):
        if src == dst:
            raise ApiError(422, "same_group", "cannot merge a group into itself")
        s, d = self.get_group(pid, src), self.get_group(pid, dst)
        with self.lock:
            self.db.execute("UPDATE crash_reports SET group_id=? WHERE group_id=?", (dst, src))
            self.db.execute("UPDATE crash_groups SET first_seen=MIN(first_seen,?), last_seen=MAX(last_seen,?) WHERE id=?",
                            (s["first_seen"], s["last_seen"], dst))
            self.db.execute("UPDATE notes SET group_id=? WHERE group_id=?", (dst, src))
            self.db.execute("UPDATE crash_groups SET status='ignored', title=? WHERE id=?", ("[merged into #%d] %s" % (dst, s["title"]), src))
            self.db.commit()
        self.audit(pid, actor, "group.merge", "group:%d" % dst, "merged group %d (%s) into %d" % (src, s["signature"][:12], dst))
        self.audit(pid, actor, "group.merge", "group:%d" % src, "merged into group %d" % dst)
        return self.get_group(pid, dst)

    def split_report(self, pid, gid, report_id, actor):
        self.get_group(pid, gid)
        r = self._one("SELECT * FROM crash_reports WHERE id=? AND project_id=? AND group_id=?", (report_id, pid, gid))
        if not r:
            raise ApiError(404, "not_found", "report not in this group")
        sig = "manual-%s" % secrets.token_hex(8)
        with self.lock:
            cur = self.db.execute(
                "INSERT INTO crash_groups(project_id,signature,signature_version,title,crash_type,status,severity,explanation,first_seen,last_seen) "
                "VALUES(?,?,?,?,?,?,?,?,?,?)",
                (pid, sig, grouping.SIGNATURE_VERSION, "[split from #%d] %s" % (gid, r["crash_type"]), r["crash_type"], "new", "medium",
                 "manually split from group %d by %s" % (gid, actor), r["occurred_at"], r["occurred_at"]))
            self.db.execute("UPDATE crash_reports SET group_id=? WHERE id=?", (cur.lastrowid, report_id))
            self.db.commit()
        self.audit(pid, actor, "group.split", "group:%d" % gid, "report %d moved to new group %d" % (report_id, cur.lastrowid))
        return self.get_group(pid, cur.lastrowid)

    # ---- analytics (all computed from stored rows)
    def stats(self, pid, days):
        since = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - days * 86400))
        fatal = "project_id=? AND kind='fatal' AND occurred_at>=?"
        total = self._one("SELECT COUNT(*) c FROM crash_reports WHERE " + fatal, (pid, since))["c"]
        return {
            "period_days": days,
            "total_fatal_reports": total,
            "total_diagnostics": self._one("SELECT COUNT(*) c FROM crash_reports WHERE project_id=? AND kind='diagnostic' AND occurred_at>=?", (pid, since))["c"],
            "unique_groups": self._one("SELECT COUNT(DISTINCT group_id) c FROM crash_reports WHERE " + fatal, (pid, since))["c"],
            "new_groups": self._one("SELECT COUNT(*) c FROM crash_groups WHERE project_id=? AND first_seen>=?", (pid, since))["c"],
            "by_version": self._q("SELECT app_version version, COUNT(*) crashes FROM crash_reports WHERE %s GROUP BY app_version ORDER BY crashes DESC" % fatal, (pid, since)),
            "trend": self._q("SELECT substr(occurred_at,1,10) day, COUNT(*) crashes FROM crash_reports WHERE %s GROUP BY day ORDER BY day" % fatal, (pid, since)),
            "top_groups": self._q("SELECT g.id, g.title, g.status, COUNT(*) crashes FROM crash_reports r JOIN crash_groups g ON g.id=r.group_id "
                                  "WHERE r.project_id=? AND r.kind='fatal' AND r.occurred_at>=? GROUP BY g.id ORDER BY crashes DESC LIMIT 5", (pid, since)),
            "processing": self._q("SELECT processing_status status, COUNT(*) c FROM crash_reports WHERE project_id=? GROUP BY processing_status", (pid,)),
            "recent_audit": self._q("SELECT actor,action,target,detail,created_at FROM audit_events WHERE project_id=? ORDER BY id DESC LIMIT 10", (pid,)),
            "not_measured": ["crash-free sessions (no session instrumentation exists)", "unique users/devices (SDK sends no identifier)"],
        }

    def audit_log(self, pid, limit=100):
        return self._q("SELECT actor,action,target,detail,created_at FROM audit_events WHERE project_id=? ORDER BY id DESC LIMIT ?", (pid, min(limit, 500)))

    # ---- retention
    def purge_older_than(self, pid, days, actor):
        cutoff = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - days * 86400))
        rows = self._q("SELECT id, artifact_path FROM crash_reports WHERE project_id=? AND received_at<=?", (pid, cutoff))
        for r in rows:
            try:
                os.remove(r["artifact_path"])
            except FileNotFoundError:
                pass
        with self.lock:
            self.db.execute("DELETE FROM crash_reports WHERE project_id=? AND received_at<=?", (pid, cutoff))
            self.db.commit()
        self.audit(pid, actor, "retention.purge", "reports", "deleted %d reports older than %d days" % (len(rows), days))
        return len(rows)
