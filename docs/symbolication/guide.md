# Symbolication guide (Linux ELF/DWARF)

1. Build with debug info and a build-id: `-g -Wl,--build-id`. Verify: `readelf -n app | grep "Build ID"`.
2. Upload the **unstripped** binary (or a debug file with the same build-id) with a project API key:
   `python3 scripts/cs_client.py upload-symbols --key <KEY> --binary path/to/app`.
   The server computes the file's build-id itself; a claimed `X-Build-Id` that differs is rejected (HTTP 422); non-ELF is rejected.
3. Reports are resolved per frame by `addr2line`, using only the symbol file whose build-id equals the module's build-id
   in that report. No match ⇒ the frame stays `unresolved_*`; nothing is guessed. Return addresses are looked up at `offset-1`.
4. Reports ingested before symbols existed: call `POST /api/v1/reports/{id}/retry?project_id=…` (dashboard: "Reprocess"). Regrouping is audited.

Not implemented: Windows PDB, separate `.debug` files / debuginfod, inlined-frame expansion.
