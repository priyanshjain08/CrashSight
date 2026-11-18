#!/usr/bin/env bash
# Plain g++ build used when CMake is unavailable. Output goes to ./build.
# Usage: scripts/build_native.sh [debug|asan]
set -euo pipefail
cd "$(dirname "$0")/.."
mode="${1:-debug}"
flags=(-std=c++20 -g -O0 -fno-omit-frame-pointer -Wall -Wextra -Wpedantic -Werror -Isdk/include -Isdk/src)
[ "$mode" = asan ] && flags+=(-fsanitize=address,undefined)
mkdir -p build/obj
for f in crashsight platform_posix serialization; do
  g++ "${flags[@]}" -c "sdk/src/$f.cpp" -o "build/obj/$f.o"
done
rm -f build/libcrashsight.a && ar rcs build/libcrashsight.a build/obj/*.o
g++ "${flags[@]}" examples/basic-cpp-app/main.cpp build/libcrashsight.a -pthread -rdynamic -Wl,--build-id -o build/basic_cpp_app
gcc -std=c11 -g -O0 -Wall -Wextra -Werror -Isdk/include -c examples/basic-c-app/main.c -o build/obj/c_main.o
g++ ${mode:+$( [ "$mode" = asan ] && echo -fsanitize=address,undefined )} build/obj/c_main.o build/libcrashsight.a -pthread -Wl,--build-id -o build/basic_c_app
g++ "${flags[@]}" sdk/tests/test_sdk.cpp build/libcrashsight.a -pthread -o build/test_sdk
echo "native build ($mode) OK"
