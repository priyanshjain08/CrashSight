"""Backend integration tests (stdlib unittest; pytest was not installable offline).
Run from backend/:  python3 -m unittest discover -s tests -v
Needs the sample binary: scripts/build_native.sh (native tests skip if absent)."""
import glob
import http.client
import json
import os
import shutil
import subprocess
import tempfile
import threading
import unittest

from crashsight_server.server import create_server
from crashsight_server import grouping

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
APP = os.path.join(ROOT, "build", "basic_cpp_app")
TOKEN = "test-admin-token-0123456789"


def crash_report(scenario, version="1.0.0"):
    """Run the real sample app, trigger a controlled crash, return the finalized JSON report text."""
    out = tempfile.mkdtemp(prefix="cs-bt-")
    try:
        subprocess.run([APP, "--out=" + out, "--crash=" + scenario, "--version=" + version], capture_output=True)
        subprocess.run([APP, "--out=" + out], capture_output=True)  # next start finalizes the raw record
        for p in glob.glob(out + "/*.json"):
            if '"kind": "fatal"' in open(p).read():
                return open(p).read()
        raise AssertionError("no fatal report produced")
    finally:
        shutil.rmtree(out, ignore_errors=True)


class Api:
    def __init__(self, port):
        self.port = port

    def call(self, method, path, body=None, headers=None, raw=None):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=30)
        h = dict(headers or {})
        data = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
        if data is not None:
            h["Content-Length"] = str(len(data))
        c.request(method, path, body=data, headers=h)
        r = c.getresponse()
        payload = r.read()
        c.close()
        try:
            return r.status, json.loads(payload)
        except ValueError:
            return r.status, payload

    def admin(self, method, path, body=None):
        return self.call(method, path, body, {"Authorization": "Bearer " + TOKEN})


class BackendCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.mkdtemp(prefix="cs-data-")
        cls.srv = create_server(cls.dir, TOKEN, port=0, rate_per_minute=100000)
        cls.srv.RequestHandlerClass.log_message = lambda *a, **k: None  # quiet test output
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.api = Api(cls.srv.server_address[1])

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()
        shutil.rmtree(cls.dir, ignore_errors=True)

    def new_project(self, name):
        s, r = self.api.admin("POST", "/api/v1/projects", {"name": name})
        self.assertEqual(s, 201, r)
        return r["project"]["id"], {"X-API-Key": r["api_key"]["key"]}

    def ingest(self, hdrs, text):
        return self.api.call("POST", "/api/v1/reports", headers=hdrs, raw=text.encode())


def diag(rid="aaaaaaaa-0000-4000-8000-000000000001", **kw):
    d = {"schema_version": 1, "report_id": rid, "kind": "diagnostic", "application_name": "A",
         "application_version": "1", "crash_type": "diagnostic", "timestamp_utc": "2026-11-18T10:00:00Z"}
    d.update(kw)
    return json.dumps(d)


class TestAuthAndValidation(BackendCase):
    def test_health_open_admin_closed(self):
        self.assertEqual(self.api.call("GET", "/api/v1/health")[0], 200)
        self.assertEqual(self.api.call("GET", "/api/v1/projects")[0], 401)
        self.assertEqual(self.api.call("GET", "/api/v1/projects", headers={"Authorization": "Bearer wrong"})[0], 401)
        self.assertEqual(self.api.admin("GET", "/api/v1/projects")[0], 200)

    def test_ingest_requires_valid_key(self):
        self.assertEqual(self.ingest({}, diag())[0], 401)
        self.assertEqual(self.ingest({"X-API-Key": "cs_nope"}, diag())[0], 401)

    def test_malformed_and_invalid_payloads(self):
        _, h = self.new_project("val")
        self.assertEqual(self.ingest(h, "not json")[0], 400)
        self.assertEqual(self.ingest(h, "[]")[0], 422)
        self.assertEqual(self.ingest(h, json.dumps({"schema_version": 99, "report_id": "aaaaaaaa"}))[0], 422)
        self.assertEqual(self.ingest(h, diag(kind="evil"))[0], 422)
        self.assertEqual(self.ingest(h, diag(frames=[{"address": "nothex"}]))[0], 422)
        self.assertEqual(self.ingest(h, diag(report_id="../../etc/passwd"))[0], 422)
        s, r = self.ingest(h, diag(newer_unknown_field={"x": 1}, schema_version=1))
        self.assertEqual(s, 201, r)  # unknown fields tolerated

    def test_oversized_rejected(self):
        _, h = self.new_project("big")
        s, r = self.ingest(h, diag(message="x" * 1024) + " " * (1 << 20))
        self.assertEqual(s, 413)

    def test_duplicate_report_id(self):
        _, h = self.new_project("dup")
        self.assertEqual(self.ingest(h, diag())[0], 201)
        self.assertEqual(self.ingest(h, diag())[0], 409)

    def test_api_key_revocation(self):
        pid, h = self.new_project("rev")
        s, keys = self.api.admin("GET", "/api/v1/projects/%d/keys" % pid)
        self.assertEqual(self.api.admin("DELETE", "/api/v1/projects/%d/keys/%d" % (pid, keys["items"][0]["id"]))[0], 200)
        self.assertEqual(self.ingest(h, diag())[0], 401)

    def test_key_stored_hashed(self):
        pid, h = self.new_project("hash")
        rows = self.srv.store._q("SELECT key_hash, prefix FROM api_keys WHERE project_id=?", (pid,))
        self.assertNotIn(h["X-API-Key"], json.dumps(rows))
        self.assertEqual(len(rows[0]["key_hash"]), 64)

    def test_project_name_validation_and_conflict(self):
        self.assertEqual(self.api.admin("POST", "/api/v1/projects", {"name": "<script>"})[0], 400)
        self.new_project("same")
        self.assertEqual(self.api.admin("POST", "/api/v1/projects", {"name": "same"})[0], 409)


class TestIsolationAndPaging(BackendCase):
    def test_project_isolation(self):
        pa, ha = self.new_project("iso-a")
        pb, hb = self.new_project("iso-b")
        s, ra = self.ingest(ha, diag("bbbbbbbb-0000-4000-8000-000000000001"))
        self.assertEqual(s, 201)
        # project B cannot read project A's report by id, even as admin scoped to B
        self.assertEqual(self.api.admin("GET", "/api/v1/reports/%d?project_id=%d" % (ra["id"], pb))[0], 404)
        self.assertEqual(self.api.admin("GET", "/api/v1/reports/%d/raw?project_id=%d" % (ra["id"], pb))[0], 404)
        self.assertEqual(self.api.admin("GET", "/api/v1/reports/%d?project_id=%d" % (ra["id"], pa))[0], 200)
        _, lb = self.api.admin("GET", "/api/v1/reports?project_id=%d" % pb)
        self.assertEqual(lb["total"], 0)

    def test_same_report_id_allowed_across_projects(self):
        _, ha = self.new_project("x-a")
        _, hb = self.new_project("x-b")
        self.assertEqual(self.ingest(ha, diag("cccccccc-0000-4000-8000-000000000001"))[0], 201)
        self.assertEqual(self.ingest(hb, diag("cccccccc-0000-4000-8000-000000000001"))[0], 201)

    def test_pagination_and_filters(self):
        pid, h = self.new_project("page")
        for i in range(7):
            self.assertEqual(self.ingest(h, diag("dddddddd-0000-4000-8000-%012d" % i))[0], 201)
        _, p1 = self.api.admin("GET", "/api/v1/reports?project_id=%d&limit=3&offset=0" % pid)
        _, p3 = self.api.admin("GET", "/api/v1/reports?project_id=%d&limit=3&offset=6" % pid)
        self.assertEqual((p1["total"], len(p1["items"]), len(p3["items"])), (7, 3, 1))
        _, k = self.api.admin("GET", "/api/v1/reports?project_id=%d&kind=fatal" % pid)
        self.assertEqual(k["total"], 0)
        self.assertEqual(self.api.admin("GET", "/api/v1/groups?project_id=%d&sort=bogus" % pid)[0], 400)
        self.assertEqual(self.api.admin("GET", "/api/v1/reports")[0], 400)

    def test_rate_limit(self):
        from crashsight_server.server import RateLimiter
        rl = RateLimiter(3)
        self.assertEqual([rl.allow("k") for _ in range(5)], [True, True, True, False, False])

    def test_context_masking_and_retention(self):
        pid, h = self.new_project("mask")
        s, r = self.ingest(h, diag("eeeeeeee-0000-4000-8000-000000000001", context={"api_token": "hunter2", "mode": "x"}))
        self.assertEqual(s, 201)
        self.assertEqual(r["context"], {"api_token": "***", "mode": "x"})
        s, out = self.api.admin("POST", "/api/v1/projects/%d/purge" % pid, {"older_than_days": 0})
        self.assertEqual((s, out["deleted"]), (200, 1))
        _, lst = self.api.admin("GET", "/api/v1/reports?project_id=%d" % pid)
        self.assertEqual(lst["total"], 0)
        _, audit = self.api.admin("GET", "/api/v1/audit?project_id=%d" % pid)
        self.assertIn("retention.purge", [a["action"] for a in audit["items"]])


@unittest.skipUnless(os.path.exists(APP), "sample app not built (scripts/build_native.sh)")
class TestPipeline(BackendCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.null1, cls.null2 = crash_report("null-deref"), crash_report("null-deref", "1.0.1")
        cls.abort = crash_report("abort")

    def sym_upload(self, h, binary=APP, build_id=None):
        hdrs = dict(h)
        if build_id:
            hdrs["X-Build-Id"] = build_id
        with open(binary, "rb") as f:
            data = f.read()
        return self.api.call("POST", "/api/v1/symbols?module=basic_cpp_app", headers=hdrs, raw=data)

    def test_equivalent_crashes_group_unrelated_stay_separate(self):
        pid, h = self.new_project("pipe")
        s, a = self.ingest(h, self.null1); self.assertEqual(s, 201)
        s, b = self.ingest(h, self.null2); self.assertEqual(s, 201)
        s, c = self.ingest(h, self.abort); self.assertEqual(s, 201)
        # addresses differ between runs (ASLR) but the signature does not
        self.assertNotEqual(a["frames"][0]["address"], b["frames"][0]["address"])
        self.assertEqual(a["group_id"], b["group_id"])
        self.assertNotEqual(a["group_id"], c["group_id"])
        _, g = self.api.admin("GET", "/api/v1/groups/%d?project_id=%d" % (a["group_id"], pid))
        self.assertEqual(g["occurrences"], 2)
        self.assertEqual(g["affected_versions"], ["1.0.0", "1.0.1"])
        self.assertIn("signature v1", g["explanation"])

    def test_symbolication_matches_build_id_only(self):
        pid, h = self.new_project("sym")
        s, r = self.ingest(h, self.null1)
        self.assertEqual(r["symbolication_status"], "unresolved")  # no symbols registered yet
        self.assertTrue(all(f["status"] != "symbolicated" for f in r["frames"]))
        s, reg = self.sym_upload(h); self.assertEqual(s, 201, reg)
        s, r2 = self.api.admin("POST", "/api/v1/reports/%d/retry?project_id=%d" % (r["id"], pid))
        self.assertEqual(s, 200)
        fns = [f.get("function") for f in r2["frames"]]
        self.assertTrue(any(fn and "level3" in fn for fn in fns), fns)
        self.assertIn(r2["symbolication_status"], ("partial", "symbolicated"))
        lvl3 = next(f for f in r2["frames"] if f.get("function") and "level3" in f["function"])
        self.assertTrue(lvl3["source_file"].endswith("main.cpp") and lvl3["line"] > 0)
        # libc frames stay explicitly unresolved, never guessed
        self.assertTrue(any(f["status"] == "unresolved_no_symbols" for f in r2["frames"]))

    def test_symbol_mismatch_and_garbage_rejected(self):
        pid, h = self.new_project("symbad")
        self.assertEqual(self.sym_upload(h, build_id="0" * 40)[0], 422)
        self.assertEqual(self.api.call("POST", "/api/v1/symbols", headers=h, raw=b"#!/bin/sh\necho hi")[0], 422)

    def test_symbols_are_per_project(self):
        pa, ha = self.new_project("symiso-a")
        pb, hb = self.new_project("symiso-b")
        self.assertEqual(self.sym_upload(ha)[0], 201)
        s, r = self.ingest(hb, self.null1)  # project B has no symbols: must NOT use A's
        self.assertTrue(all(f["status"] != "symbolicated" for f in r["frames"]))

    def test_regroup_after_symbols_is_audited(self):
        pid, h = self.new_project("regroup")
        s, r = self.ingest(h, self.null1)
        before = r["group_id"]
        self.sym_upload(h)
        s, r2 = self.api.admin("POST", "/api/v1/reports/%d/retry?project_id=%d" % (r["id"], pid))
        self.assertNotEqual(r2["group_id"], before)  # signature now uses function names
        _, audit = self.api.admin("GET", "/api/v1/audit?project_id=%d" % pid)
        self.assertIn("report.regroup", [a["action"] for a in audit["items"]])

    def test_lifecycle_notes_merge_split_reopen(self):
        pid, h = self.new_project("life")
        _, a = self.ingest(h, self.null1)
        _, c = self.ingest(h, self.abort)
        gid = a["group_id"]
        q = "?project_id=%d" % pid
        s, g = self.api.admin("PATCH", "/api/v1/groups/%d%s" % (gid, q), {"status": "investigating", "assignee": "dev1", "severity": "high"})
        self.assertEqual((s, g["status"], g["assignee"], g["severity"]), (200, "investigating", "dev1", "high"))
        self.assertEqual(self.api.admin("PATCH", "/api/v1/groups/%d%s" % (gid, q), {"status": "bogus"})[0], 422)
        s, g = self.api.admin("POST", "/api/v1/groups/%d/notes%s" % (gid, q), {"body": "looks like null write in level3"})
        self.assertEqual(g["notes"][0]["body"], "looks like null write in level3")
        self.api.admin("PATCH", "/api/v1/groups/%d%s" % (gid, q), {"status": "resolved"})
        self.ingest(h, self.null2)  # regression: same crash after resolve
        _, g = self.api.admin("GET", "/api/v1/groups/%d%s" % (gid, q))
        self.assertEqual(g["status"], "reopened")
        # split one report out, then merge it back
        s, newg = self.api.admin("POST", "/api/v1/groups/%d/split%s" % (gid, q), {"report_id": a["id"]})
        self.assertEqual(s, 201)
        s, merged = self.api.admin("POST", "/api/v1/groups/%d/merge%s" % (newg["id"], q), {"into": gid})
        self.assertEqual(merged["occurrences"], 2)
        actions = [x["action"] for x in merged["history"]]
        self.assertIn("group.merge", actions)
        _, audit = self.api.admin("GET", "/api/v1/audit?project_id=%d" % pid)
        acts = {x["action"] for x in audit["items"]}
        self.assertTrue({"group.update", "group.note", "group.split", "group.merge", "group.reopen"} <= acts, acts)
        # originals preserved
        self.assertEqual(self.api.admin("GET", "/api/v1/reports/%d/raw?project_id=%d" % (a["id"], pid))[0], 200)

    def test_stats_come_from_stored_data(self):
        pid, h = self.new_project("stats")
        _, s0 = self.api.admin("GET", "/api/v1/stats?project_id=%d&days=3650" % pid)
        self.assertEqual((s0["total_fatal_reports"], s0["unique_groups"]), (0, 0))
        self.ingest(h, self.null1); self.ingest(h, self.null2); self.ingest(h, self.abort)
        _, s1 = self.api.admin("GET", "/api/v1/stats?project_id=%d&days=3650" % pid)
        self.assertEqual((s1["total_fatal_reports"], s1["unique_groups"], s1["new_groups"]), (3, 2, 2))
        self.assertEqual(sum(v["crashes"] for v in s1["by_version"]), 3)
        self.assertTrue(s1["not_measured"])


class TestGroupingUnit(unittest.TestCase):
    def frames(self, base, offs):
        return [{"module": "/opt/app/bin/app", "module_offset": o, "address": hex(base + o)} for o in offs]

    def test_aslr_does_not_change_signature(self):
        a = grouping.compute_signature("SIGSEGV", self.frames(0x55550000, [0x10, 0x20]))[0]
        b = grouping.compute_signature("SIGSEGV", self.frames(0x77770000, [0x10, 0x20]))[0]
        self.assertEqual(a, b)

    def test_different_crash_type_or_stack_differs(self):
        f = self.frames(0, [0x10, 0x20])
        self.assertNotEqual(grouping.compute_signature("SIGSEGV", f)[0], grouping.compute_signature("SIGABRT", f)[0])
        self.assertNotEqual(grouping.compute_signature("SIGSEGV", f)[0],
                            grouping.compute_signature("SIGSEGV", self.frames(0, [0x10, 0x30]))[0])

    def test_system_frames_ignored(self):
        app = self.frames(0, [0x10])
        libc = [{"module": "/lib/x86_64-linux-gnu/libc.so.6", "module_offset": 0x99, "address": "0x1"}]
        self.assertEqual(grouping.compute_signature("SIGSEGV", libc + app)[0], grouping.compute_signature("SIGSEGV", app)[0])


if __name__ == "__main__":
    unittest.main()
