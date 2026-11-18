# UNVERIFIED: CMake was not available in the environment where this project was
# developed. The same sources are built and tested with scripts/build_native.sh (g++).
# Please run the commands in README.md on your machine and report any problems.
cmake_minimum_required(VERSION 3.20)
project(CrashSight VERSION 0.1.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 11)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Only the POSIX/Linux adapter is implemented. There is NO Windows crash-capture
# adapter yet, so refuse to configure instead of producing a broken SDK.
if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
  message(FATAL_ERROR "CrashSight currently supports Linux only (Windows/macOS adapters are not implemented).")
endif()

option(CRASHSIGHT_SANITIZE "Build with AddressSanitizer + UBSan" OFF)
option(CRASHSIGHT_BUILD_TESTS "Build tests" ON)
option(CRASHSIGHT_BUILD_EXAMPLES "Build examples" ON)

add_compile_options(-Wall -Wextra -Wpedantic -fno-omit-frame-pointer)
if(CRASHSIGHT_SANITIZE)
  add_compile_options(-fsanitize=address,undefined)
  add_link_options(-fsanitize=address,undefined)
endif()

find_package(Threads REQUIRED)
add_library(crashsight STATIC
  sdk/src/crashsight.cpp sdk/src/platform_posix.cpp sdk/src/serialization.cpp)
target_include_directories(crashsight
  PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/sdk/include> $<INSTALL_INTERFACE:include>
  PRIVATE sdk/src)
target_link_libraries(crashsight PUBLIC Threads::Threads ${CMAKE_DL_LIBS})

if(CRASHSIGHT_BUILD_EXAMPLES)
  add_executable(basic_cpp_app examples/basic-cpp-app/main.cpp)
  target_link_libraries(basic_cpp_app PRIVATE crashsight)
  target_link_options(basic_cpp_app PRIVATE -rdynamic -Wl,--build-id)
  add_executable(basic_c_app examples/basic-c-app/main.c)
  target_link_libraries(basic_c_app PRIVATE crashsight stdc++)
  target_link_options(basic_c_app PRIVATE -Wl,--build-id)
endif()

if(CRASHSIGHT_BUILD_TESTS)
  enable_testing()
  add_executable(test_sdk sdk/tests/test_sdk.cpp)
  target_link_libraries(test_sdk PRIVATE crashsight)
  add_test(NAME sdk_unit COMMAND test_sdk)
  add_executable(bench_serialization sdk/bench/bench_serialization.cpp)
  target_link_libraries(bench_serialization PRIVATE crashsight)
endif()

install(TARGETS crashsight ARCHIVE DESTINATION lib)
install(DIRECTORY sdk/include/ DESTINATION include)
