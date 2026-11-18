# Security and privacy notes

## What the SDK collects (exhaustive)
Application name/version/environment/build label; OS name and CPU architecture; UTC time; signal and fault
address; process and thread id; raw instruction addresses of the crashing stack; loaded module paths, load
addresses and ELF build-ids; and context entries *you* set explicitly (diagnostic reports only, bounded).
It does **not** collect memory contents, registers, environment variables, command lines, usernames or
network data, and it never uploads automatically. Module paths can reveal directory names — review them.

## Backend protections (implemented and tested unless noted)
* Admin endpoints need a bearer token (constant-time compare); the server refuses to start without a ≥16-char token.
* Ingest/symbol upload need a project API key: stored as SHA-256 only, shown once, revocable, per-key rate limit.
* Every data query is scoped by `project_id`; cross-project reads return 404 (tested). Symbols are stored per project.
* Size limits: reports 1 MiB, symbol files 200 MiB. Strict schema validation. `report_id` charset-restricted and
  hashed for the artifact filename (no path traversal). Symbol files must be ELF and are only *read* by
  `readelf`/`addr2line` (argument lists, no shell) — uploads are never executed.
* Context values under keys containing token/secret/password/key/auth/cookie/credential are masked in API output.
* Audit events for project/key/symbol/group/retention/regroup operations.
* Retention: `POST /projects/{id}/purge` deletes reports and artifacts older than N days (manual; not scheduled).

## Not implemented / your responsibility
TLS (run behind a reverse proxy), user accounts, encryption at rest, scheduled retention, log scrubbing beyond
not logging headers/bodies, dependency vulnerability scanning, rate limiting by IP.
