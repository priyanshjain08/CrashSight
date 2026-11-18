# Contributing
Run `scripts/build_native.sh debug && ./build/test_sdk`, `cd backend && python3 -m unittest discover -s tests`, and
`scripts/e2e_demo.sh` before opening a PR. Never claim something works unless you ran it; update the README status table.
Signal-handler code must stay async-signal-safe (see `platform_posix.cpp` header comment).
