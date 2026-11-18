#!/usr/bin/env python3
"""Tiny CLI for CrashSight (stdlib only).
  cs_client.py upload-symbols --url U --key K --binary PATH
  cs_client.py submit --url U --key K REPORT.json [REPORT.json ...]
Reports are uploaded by this tool in normal context - never from the crash handler."""
import argparse, json, os, sys, urllib.request, urllib.error


def post(url, key, path, data, extra=None):
    req = urllib.request.Request(url.rstrip("/") + path, data=data, method="POST",
                                 headers={"X-API-Key": key, **(extra or {})})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("upload-symbols", "submit"):
        p = sub.add_parser(name)
        p.add_argument("--url", default=os.environ.get("CRASHSIGHT_URL", "http://127.0.0.1:8000"))
        p.add_argument("--key", default=os.environ.get("CRASHSIGHT_API_KEY", ""))
        if name == "upload-symbols":
            p.add_argument("--binary", required=True)
        else:
            p.add_argument("files", nargs="+")
    a = ap.parse_args()
    if not a.key:
        sys.exit("API key required (--key or CRASHSIGHT_API_KEY)")
    rc = 0
    if a.cmd == "upload-symbols":
        with open(a.binary, "rb") as f:
            s, r = post(a.url, a.key, "/api/v1/symbols?module=" + os.path.basename(a.binary), f.read())
        print(s, json.dumps(r)); rc = 0 if s == 201 else 1
    else:
        for path in a.files:
            with open(path, "rb") as f:
                s, r = post(a.url, a.key, "/api/v1/reports", f.read())
            print(path, s, r.get("group_id") if s == 201 else json.dumps(r)); rc |= s != 201
    sys.exit(rc)


if __name__ == "__main__":
    main()
