# CrashSight

*Understand native crashes. Find the cause. Fix with confidence.*

CrashSight is a crash-diagnostics toolkit for C and C++ programs: a small SDK that writes a local crash
report, a backend that ingests, symbolicates and groups reports, and a dashboard to investigate them.

> **Read this first — what is and isn't real.** This repository was built in a sandbox with no network
> access, no CMake, no Docker, and no FastAPI/React toolchain. Everything marked **Verified** below was
> actually executed there. Everything marked **Unverified** was written but never run. The backend uses the
> Python standard library + SQLite instead of the FastAPI + PostgreSQL stack in the original spec
> (see [Deviations](#deviations-from-the-original-spec)).

## Status

| Area | Status | Evidence |
|---|---|---|
| C++ SDK + C API (Linux) | **Verified** | 17/17 unit tests, `g++ 13 -Wall -Wextra -Wpedantic -Werror` |
| Sanitizers | **Verified** | ASan+UBSan 17/17; TSan 16/16 + 1 *skipped* (see Known limitations) |
| POSIX crash capture (SIGSEGV/SIGABRT/SIGFPE/SIGILL/SIGBUS) | **Verified** (Linux x86_64) | fork+`raise(SIGSEGV)` integration test; real null-deref sample crash |
| Versioned JSON report schema v1 | **Verified** | round-trip, malformed, oversized, old/new-version tests |
| ELF/DWARF symbolication (build-id matched, via `addr2line`) | **Verified** | backend tests + e2e: `level3(int)`, `main.cpp:<line>` |
| Crash grouping (signature v1) | **Verified** | ASLR-different crashes group; different crash type separates |
| REST API, SQLite persistence, audit log, merge/split, retention | **Verified** | 23 backend tests + 10-step e2e script |
| Dashboard (dependency-free HTML/JS) | **Partially verified** | JS syntax-checked with Node; served by backend in e2e. **Never opened in a browser** |
| CMake build, CTest | **Unverified** | CMake not installed in sandbox |
| Docker / Compose, GitHub Actions | **Unverified** | never run |
| Windows (MSVC, minidump, PDB) | **Not implemented** | CMake refuses to configure on non-Linux |
| macOS | **Not implemented** | |
| PostgreSQL, Alembic, FastAPI, React/Vite/Tailwind | **Not implemented** | see Deviations |
| Multi-user accounts, per-user roles | **Not implemented** | single admin token + per-project API keys |
| Crash-free sessions, unique users | **Not implemented** | no session/identity instrumentation exists; never faked |

## Quick start (Linux)

Prerequisites: `g++` (C++20), `binutils` (`readelf`, `addr2line`), Python 3.12+, `curl`. CMake optional.

```bash
scripts/build_native.sh debug            # builds SDK, samples, tests -> ./build
./build/test_sdk                         # native unit tests
(cd backend && python3 -m unittest discover -s tests -v)   # backend tests
scripts/e2e_demo.sh                      # full end-to-end workflow
```

With CMake (unverified): `cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug && cmake --build build && ctest --test-dir build --output-on-failure`

### Run the server and dashboard

```bash
export CRASHSIGHT_ADMIN_TOKEN="$(python3 -c 'import secrets;print(secrets.token_urlsafe(24))')"
PYTHONPATH=backend python3 -m crashsight_server.server      # http://127.0.0.1:8000
```
Open http://127.0.0.1:8000, click **Admin token**, paste the token, create a project (the API key is shown **once**).

### Demo by hand

```bash
./build/basic_cpp_app --out=./crash-reports --crash=null-deref   # LOCAL TESTING ONLY: crashes on purpose
./build/basic_cpp_app --out=./crash-reports                      # normal start finalizes the crash record to JSON
python3 scripts/cs_client.py upload-symbols --key <API_KEY> --binary build/basic_cpp_app
python3 scripts/cs_client.py submit --key <API_KEY> crash-reports/*.json
```
Samples never crash unless you pass `--crash=<scenario>` (`null-deref`, `abort`, `divide-zero`; C sample: `--crash`).

## SDK usage

C++:
```cpp
#include "crashsight/crashsight.hpp"
crashsight::Options o;
o.application_name = "MyApp"; o.application_version = "1.0.0"; o.local_output_directory = "./crash-reports";
crashsight::Session session(o);                 // RAII: initialize + shutdown
crashsight::set_context("feature", "checkout"); // bounded: 32 entries, 64/256 chars
crashsight::report_diagnostic("cache miss storm");   // nonfatal event
```
C:
```c
cs_options o = {"MyApp", "1.0.0", "production", NULL, "./crash-reports"};
cs_initialize(&o); cs_report_diagnostic("hello", NULL, 0); cs_shutdown();
```
Link with `-Wl,--build-id` (required to match symbols) and build with `-g`. See `docs/`.

## How it works

```
app (SDK) --signal--> raw record (.csraw, async-signal-safe)
next start --> JSON report (schema v1) --upload (separate step)--> backend
backend: validate -> store original -> symbolicate (build-id match) -> signature -> group -> stats -> dashboard
```
The SDK never uploads from a crash handler. Upload is a separate, explicit step (`scripts/cs_client.py`).

## Deviations from the original spec

* **Backend stack:** stdlib `http.server` + `sqlite3` instead of FastAPI/Pydantic/SQLAlchemy/Alembic/PostgreSQL —
  those packages could not be installed offline. Schema is created by `CREATE TABLE IF NOT EXISTS` (no migrations).
  `http.server` is adequate for local/dev use, **not** for production exposure; put it behind a TLS reverse proxy.
* **Frontend:** one dependency-free HTML/JS file instead of React/TypeScript/Vite/Tailwind/TanStack Query.
* **Tests:** custom C++ harness and `unittest` instead of GoogleTest/Catch2 and pytest (not installable).
* **JSON:** hand-written writer/parser (bounded depth/size) instead of nlohmann/json.
* **Auth:** one admin bearer token for dashboard/admin endpoints + hashed per-project API keys. No user accounts.
* **Not done:** frontend tests, accessibility audit, Docker image build, minidump support, clang-tidy/clang-format
  runs, vulnerability scans, Windows adapter, multi-tenancy, Redis/queue (not needed so far).

## Known limitations

* In-process crash handling cannot capture every failure (heap corruption, stack overflow beyond the 64 KiB
  alternate stack, `SIGKILL`, power loss). `backtrace()` is not formally async-signal-safe; it is primed at init.
* The signal handler's first two frames are dropped assuming glibc/x86_64 layout.
* Modules loaded with `dlopen` after `initialize()` are not in the module table.
* Fatal reports do **not** include custom context (it is mutable state; copying it in the handler would be unsafe).
* Grouping uses function names when symbols exist and module+offset otherwise, so reports ingested *before*
  symbols are uploaded land in a different group until reprocessed (`POST /reports/{id}/retry`, audited).
* TSan cannot run the fatal-capture test (its instrumentation faults inside the handler on the alternate
  stack); that test is reported as **skipped** under TSan.
* Only unstripped ELF with a GNU build-id can be symbolicated. Separate-debug-file lookup is not implemented.
* Benchmarks exist only for serialization (see `docs/development/testing.md`); other benchmarks are **not measured**.

## Layout

`sdk/` SDK + tests + bench · `backend/crashsight_server/` API, pipeline, symbolication, grouping ·
`dashboard/` UI · `examples/` samples · `scripts/` build/e2e/client · `docs/` guides.

License: MIT.
