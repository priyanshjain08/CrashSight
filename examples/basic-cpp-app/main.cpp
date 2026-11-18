// CrashSight C++ sample. Normal startup NEVER crashes.
// Controlled crash (LOCAL TESTING ONLY, opt-in):  basic_cpp_app --crash=<scenario>
// Scenarios: null-deref | abort | divide-zero | recursion-a | recursion-b
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

#include "crashsight/crashsight.hpp"

// noinline + distinct names give stable, symbolicatable frames.
__attribute__((noinline)) static void level3(int scenario) {
    if (scenario == 0) {
        volatile int* p = nullptr;
        *p = 42;  // deliberate null write; only reachable with --crash=null-deref
    } else if (scenario == 1) {
        std::abort();
    } else if (scenario == 2) {
        std::raise(SIGFPE);  // portable stand-in for integer divide by zero
    }
}
__attribute__((noinline)) static void level2(int scenario) { level3(scenario); asm volatile("" ::: "memory"); }
__attribute__((noinline)) static void level1(int scenario) { level2(scenario); asm volatile("" ::: "memory"); }

int main(int argc, char** argv) {
    std::string crash;
    std::string dir = "./crash-reports";
    std::string version = "1.0.0";
    for (int i = 1; i < argc; ++i) {
        if (std::strncmp(argv[i], "--crash=", 8) == 0) crash = argv[i] + 8;
        else if (std::strncmp(argv[i], "--out=", 6) == 0) dir = argv[i] + 6;
        else if (std::strncmp(argv[i], "--version=", 10) == 0) version = argv[i] + 10;
    }
    crashsight::Options options;
    options.application_name = "BasicCppApp";
    options.application_version = version;
    options.environment = "development";
    options.build_id = "sample-build";
    options.local_output_directory = dir;
    crashsight::Session session(options);
    if (session.status() != crashsight::Status::Ok) {
        std::fprintf(stderr, "CrashSight init failed: %s\n", crashsight::to_string(session.status()));
        return 2;
    }
    crashsight::set_context("feature", "sample");

    std::string path;
    if (crashsight::report_diagnostic("sample started", &path) == crashsight::Status::Ok)
        std::printf("diagnostic written: %s\n", path.c_str());

    if (crash.empty()) {
        std::printf("normal run complete (no crash requested)\n");
        return 0;
    }
    std::printf("LOCAL TESTING ONLY: triggering controlled crash '%s'\n", crash.c_str());
    if (crash == "null-deref") level1(0);
    else if (crash == "abort") level1(1);
    else if (crash == "divide-zero") level1(2);
    else { std::fprintf(stderr, "unknown scenario '%s'\n", crash.c_str()); return 3; }
    return 0;
}
