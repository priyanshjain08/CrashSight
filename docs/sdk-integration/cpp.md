# C++ integration

1. Build the SDK (`scripts/build_native.sh` or CMake) and link `libcrashsight.a` (needs `-pthread`).
2. Compile your app with `-g` and link with `-Wl,--build-id` (and `-rdynamic` is harmless). Do not strip the binary you upload as symbols.
3. Initialize early in `main`:
```cpp
crashsight::Options o;
o.application_name = "MyApp"; o.application_version = "1.0.0";
o.environment = "production"; o.build_id = "ci-1234"; o.local_output_directory = "/var/lib/myapp/crashes";
crashsight::Session session(o);
if (session.status() != crashsight::Status::Ok) { /* continue without crash capture */ }
```
All calls return `Status`; none throw. Calling `initialize` twice returns `AlreadyInitialized`.
`report_diagnostic()` writes a nonfatal report immediately (normal context only — never call it from a signal handler).
Crash records are converted to JSON the **next time** your app (or any SDK user of that directory) initializes, or by calling
`crashsight::finalize_pending_crashes(dir)`. Uploading is a separate step: `scripts/cs_client.py submit`.
Consuming from CMake: `add_subdirectory(CrashSight)` then `target_link_libraries(app PRIVATE crashsight)` (unverified).
