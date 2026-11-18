# Testing — commands and observed results

Environment where results were observed: Linux 6.18 x86_64, 1 vCPU Intel Xeon @ 2.30 GHz, g++ 13.3.0, Python 3.12.3, Node 22.
Status words: Passed / Failed / Skipped / Not run. CMake, Docker and GitHub Actions: **Not run** (unavailable).

| Command | Result |
|---|---|
| `scripts/build_native.sh debug` (`-Wall -Wextra -Wpedantic -Werror`) | Passed (built) |
| `./build/test_sdk` | 17 run, 17 passed, 0 failed, 0 skipped |
| ASan+UBSan build of `test_sdk` (`ASAN_OPTIONS=handle_segv=0`) | 17 run, 17 passed |
| TSan build of `test_sdk` | 16 passed, 1 **skipped** (fatal-capture test; TSan aborts inside the alt-stack handler) |
| `cd backend && python3 -m unittest discover -s tests -v` | 23 run, 23 passed |
| `scripts/e2e_demo.sh` | 10 checks passed, exit 0 |
| `node --check` on dashboard script | Passed (syntax only) |
| Dashboard UI tests, accessibility audit, clang-tidy, clang-format, vulnerability scans | **Not run** |

Test-time bugs found and fixed: handler exited instead of dying from the signal; deadlock when finalizing crash
records inside `initialize()`; crash reports carried the finalizing process's identity; purge boundary off by one second.

## Benchmark (serialization only)
`g++ -std=c++20 -O2 -DNDEBUG -Isdk/include -Isdk/src sdk/bench/bench_serialization.cpp sdk/src/*.cpp -pthread`
Dataset: one synthetic 5192-byte report (32 frames, 20 modules, 16 context entries), 20 000 iterations, 3 runs.
Observed: `to_json` 10.2–16.3 µs/op, `from_json` 23.0–24.2 µs/op. Single shared vCPU, so expect noise.
Grouping throughput, symbolication cache behaviour, SDK overhead, and pipeline throughput: **not measured**.
