# Crash report format — schema v1

A report is one UTF-8 JSON object, at most 1 MiB. Produced by the SDK; validated by `backend/crashsight_server/schema.py`.

| Field | Type | Notes |
|---|---|---|
| `schema_version` | int | `1`. Versions below 1 or above the server's current version are rejected |
| `report_id` | string | random UUIDv4, hex and `-` only, ≤64 chars |
| `sdk_version`, `kind` | string | `kind` is `fatal` or `diagnostic` |
| `application_name`, `application_version` | string | required; ≤128 / ≤64 chars |
| `environment`, `build_id` | string | optional; `build_id` is the *application's* label, not the ELF build-id |
| `os`, `architecture`, `timestamp_utc` | string | ISO-8601 UTC; for fatal reports it is the crash time |
| `crash_type`, `signal_or_code` | string, int | e.g. `SIGSEGV`, 11 |
| `fault_address` | hex string | faulting address from `siginfo` (`0x0` for a null dereference) |
| `process_id`, `thread_id` | int | |
| `message` | string | diagnostics only, ≤1024 chars |
| `frames[]` | array ≤128 | `address` (raw, ASLR-dependent), `module`, `module_offset` (address − module base; stable per build) |
| `modules[]` | array ≤256 | `name`, `base`, `build_id` (ELF GNU build-id, lowercase hex) |
| `context` | object | ≤32 string entries; keys ≤64, values ≤256 chars; absent from fatal reports |
| `capture_method`, `capture_limitations` | string | how the report was captured and what it may miss |

Raw addresses, resolved symbols and unresolved frames are kept apart: the SDK only ever writes raw
addresses. `function`, `source_file`, `line` and a per-frame `status` (`symbolicated`,
`unresolved_no_symbols`, `unresolved_no_match`, `error`) are added by the backend and never fabricated.

**Compatibility:** unknown fields are ignored; a newer `schema_version` than the reader supports is rejected
rather than half-parsed. **Defensive parsing:** the C++ parser limits nesting depth (16) and size (1 MiB);
the server enforces the same size cap, types, lengths and hex formats. Fixtures live in the tests
(`sdk/tests/test_sdk.cpp`, `backend/tests/test_backend.py`).

## Raw crash record (`*.csraw`)
The signal handler writes a line-oriented text record (`CSRAW1`) with app identity, crash time, signal, fault
address, pid/tid, module table (base, build-id, path) and raw frame addresses. It is converted to the JSON
report by `finalize_pending_crashes()` on the next `initialize()`.
