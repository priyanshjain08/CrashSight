// Self-contained test harness (no external framework available offline).
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <functional>
#include <set>
#include <sstream>
#include <thread>

#include "crashsight/crashsight.h"
#include "crashsight/crashsight.hpp"

using namespace crashsight;

static int g_failed = 0, g_run = 0, g_skipped = 0;
#define CHECK(cond)                                                          \
    do {                                                                     \
        if (!(cond)) {                                                       \
            std::printf("    CHECK FAILED %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            ++g_failed_in_test;                                              \
        }                                                                    \
    } while (0)
static int g_failed_in_test = 0;

[[maybe_unused]] static void skip(const char* name, const char* why) {
    ++g_skipped;
    std::printf("[SKIP] %s (%s)\n", name, why);
}

static void run(const char* name, const std::function<void()>& fn) {
    g_failed_in_test = 0;
    ++g_run;
    fn();
    std::printf("[%s] %s\n", g_failed_in_test ? "FAIL" : " OK ", name);
    if (g_failed_in_test) ++g_failed;
}

static std::string tmpdir(const char* tag) {
    std::string d = std::string("/tmp/cs-test-") + tag + "-" + std::to_string(::getpid());
    std::string cmd = "rm -rf '" + d + "'";
    if (std::system(cmd.c_str()) != 0) {}
    return d;
}

static std::string slurp(const std::string& p) {
    std::ifstream f(p, std::ios::binary);
    std::stringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

static Options good_options(const std::string& dir) {
    Options o;
    o.application_name = "TestApp";
    o.application_version = "1.2.3";
    o.local_output_directory = dir;
    return o;
}

int main() {
    run("config validation rejects empty name/version/dir", [] {
        Options o;
        CHECK(validate(o) == Status::InvalidArgument);
        o.application_name = "a";
        CHECK(validate(o) == Status::InvalidArgument);
        o.application_version = "1";
        CHECK(validate(o) == Status::Ok);
        o.local_output_directory = "";
        CHECK(validate(o) == Status::InvalidArgument);
    });

    run("initialize/shutdown lifecycle", [] {
        std::string d = tmpdir("life");
        CHECK(!is_initialized());
        CHECK(shutdown() == Status::NotInitialized);
        CHECK(initialize(good_options(d)) == Status::Ok);
        CHECK(is_initialized());
        CHECK(initialize(good_options(d)) == Status::AlreadyInitialized);
        CHECK(shutdown() == Status::Ok);
        CHECK(!is_initialized());
        CHECK(initialize(good_options(d)) == Status::Ok);  // re-init works
        CHECK(shutdown() == Status::Ok);
    });

    run("unavailable output directory fails gracefully", [] {
        Options o = good_options("/proc/definitely/not/writable");
        CHECK(initialize(o) == Status::IoError);
        CHECK(!is_initialized());
    });

    run("RAII session", [] {
        std::string d = tmpdir("raii");
        {
            Session s(good_options(d));
            CHECK(s.status() == Status::Ok);
            CHECK(is_initialized());
        }
        CHECK(!is_initialized());
    });

    run("report ids are unique and well-formed", [] {
        std::set<std::string> ids;
        for (int i = 0; i < 2000; ++i) ids.insert(generate_report_id());
        CHECK(ids.size() == 2000);
        std::string id = generate_report_id();
        CHECK(id.size() == 36 && id[8] == '-' && id[14] == '4');
    });

    run("bounded context", [] {
        std::string d = tmpdir("ctx");
        CHECK(set_context("k", "v") == Status::NotInitialized);
        Session s(good_options(d));
        CHECK(set_context("", "v") == Status::InvalidArgument);
        for (std::size_t i = 0; i < kMaxContextEntries; ++i)
            CHECK(set_context("key" + std::to_string(i), "v") == Status::Ok);
        CHECK(set_context("overflow", "v") == Status::TooLarge);
        CHECK(set_context("key0", "updated") == Status::Ok);  // existing keys still updatable
        std::string path;
        CHECK(report_diagnostic("x", &path) == Status::Ok);
        Report r;
        CHECK(from_json(slurp(path), &r) == Status::Ok);
        CHECK(r.context.size() == kMaxContextEntries);
        CHECK(r.context["key0"] == "updated");
    });

    run("context values are truncated", [] {
        std::string d = tmpdir("trunc");
        Session s(good_options(d));
        CHECK(set_context(std::string(500, 'k'), std::string(5000, 'v')) == Status::Ok);
        std::string path;
        CHECK(report_diagnostic("x", &path) == Status::Ok);
        Report r;
        CHECK(from_json(slurp(path), &r) == Status::Ok);
        CHECK(r.context.begin()->first.size() == kMaxContextKeyLength);
        CHECK(r.context.begin()->second.size() == kMaxContextValueLength);
    });

    run("diagnostic event writes atomic file, no temp left behind", [] {
        std::string d = tmpdir("diag");
        Session s(good_options(d));
        std::string path;
        CHECK(report_diagnostic("disk nearly full", &path) == Status::Ok);
        struct stat st{};
        CHECK(::stat(path.c_str(), &st) == 0);
        CHECK(::stat((path + ".tmp").c_str(), &st) != 0);
        Report r;
        CHECK(from_json(slurp(path), &r) == Status::Ok);
        CHECK(r.kind == "diagnostic" && r.message == "disk nearly full");
        CHECK(r.application_name == "TestApp" && r.schema_version == 1);
    });

    run("diagnostic requires initialization", [] {
        CHECK(report_diagnostic("x") == Status::NotInitialized);
    });

    run("serialization round trip incl. escapes and frames", [] {
        Report r;
        r.report_id = generate_report_id();
        r.kind = "fatal";
        r.message = "quote\" backslash\\ newline\n tab\t ctrl\x01";
        r.fault_address = 0xdeadbeefULL;
        r.frames = {{0x401000, "/bin/app", 0x1000}, {0x7fff0000, "", 0}};
        r.modules = {{"/bin/app", 0x400000, "abcd1234"}};
        r.context["a"] = "b";
        Report out;
        CHECK(from_json(to_json(r), &out) == Status::Ok);
        CHECK(out.message == r.message);
        CHECK(out.fault_address == 0xdeadbeefULL);
        CHECK(out.frames.size() == 2 && out.frames[0].module_offset == 0x1000);
        CHECK(out.modules.size() == 1 && out.modules[0].build_id == "abcd1234");
        CHECK(out.context["a"] == "b");
    });

    run("malformed reports are rejected without crashing", [] {
        Report out;
        const char* bad[] = {"", "{", "[]", "null", "{\"schema_version\":1}", "{\"schema_version\":\"x\"}",
                             "{\"schema_version\":1,\"report_id\":\"a\",\"frames\":[1]}",
                             "{\"schema_version\":1,\"report_id\":\"a\"} trailing",
                             "{\"schema_version\":1,\"report_id\":\"a\\q\"}"};
        for (const char* b : bad) CHECK(from_json(b, &out) == Status::ParseError);
        CHECK(from_json("{}", nullptr) == Status::InvalidArgument);
    });

    run("deeply nested input is bounded", [] {
        std::string deep(100000, '[');
        Report out;
        CHECK(from_json(deep, &out) == Status::ParseError);
    });

    run("oversized report rejected", [] {
        std::string big = "{\"schema_version\":1,\"report_id\":\"a\",\"message\":\"" + std::string(2 << 20, 'x') + "\"}";
        Report out;
        CHECK(from_json(big, &out) == Status::TooLarge);
    });

    run("schema compatibility: old/new/unknown fields", [] {
        Report out;
        CHECK(from_json("{\"schema_version\":0,\"report_id\":\"a\"}", &out) == Status::ParseError);
        CHECK(from_json("{\"schema_version\":2,\"report_id\":\"a\"}", &out) == Status::ParseError);
        CHECK(from_json("{\"schema_version\":1,\"report_id\":\"a\",\"future_field\":{\"x\":[1,2]}}", &out) == Status::Ok);
        CHECK(out.report_id == "a");
    });

    run("thread-safety of ordinary operations", [] {
        std::string d = tmpdir("threads");
        Session s(good_options(d));
        std::vector<std::thread> ts;
        for (int t = 0; t < 8; ++t)
            ts.emplace_back([t] {
                for (int i = 0; i < 100; ++i) {
                    set_context("t" + std::to_string(t), std::to_string(i));
                    report_diagnostic("m");
                }
            });
        for (auto& th : ts) th.join();
        CHECK(is_initialized());
    });

    run("C API interoperability", [] {
        std::string d = tmpdir("capi");
        cs_options o{"CApp", "0.1", nullptr, nullptr, d.c_str()};
        CHECK(cs_initialize(&o) == 0);
        CHECK(cs_set_context("mode", "test") == 0);
        char path[256];
        CHECK(cs_report_diagnostic("from C", path, sizeof path) == 0);
        Report r;
        CHECK(from_json(slurp(path), &r) == Status::Ok && r.message == "from C");
        CHECK(cs_set_context(nullptr, "x") != 0);
        CHECK(cs_initialize(nullptr) != 0);
        CHECK(cs_shutdown() == 0);
        CHECK(std::string(cs_status_string(0)) == "ok");
    });

#if defined(__SANITIZE_THREAD__)
    skip("fatal capture: child SIGSEGV yields a JSON report with frames and modules",
         "ThreadSanitizer aborts when instrumented handler code runs on the alternate signal stack");
    if (false)
#endif
    run("fatal capture: child SIGSEGV yields a JSON report with frames and modules", [] {
        std::string d = tmpdir("crash");
        pid_t pid = ::fork();
        if (pid == 0) {
            Options o = good_options(d);
            o.build_id = "build-42";
            if (initialize(o) != Status::Ok) ::_exit(90);
            set_context("scenario", "unit-test");
            std::raise(SIGSEGV);
            ::_exit(91);
        }
        int st = 0;
        ::waitpid(pid, &st, 0);
        CHECK(WIFSIGNALED(st) && WTERMSIG(st) == SIGSEGV);  // default action preserved
        std::vector<std::string> out;
        CHECK(finalize_pending_crashes(d, &out) == Status::Ok);
        CHECK(out.size() == 1);
        if (out.size() == 1) {
            Report r;
            CHECK(from_json(slurp(out[0]), &r) == Status::Ok);
            CHECK(r.kind == "fatal" && r.crash_type == "SIGSEGV");
            CHECK(!r.frames.empty());
            CHECK(!r.modules.empty());
            CHECK(r.process_id == static_cast<std::uint64_t>(pid));
            // Regression: identity must be the crashed process's, even though the
            // finalizing process here was never initialized.
            CHECK(r.application_name == "TestApp");
            CHECK(r.application_version == "1.2.3");
            CHECK(r.build_id == "build-42");
            CHECK(r.timestamp_utc.size() == 20);
        }
    });

    std::printf("\n%d run, %d passed, %d failed, %d skipped\n", g_run, g_run - g_failed, g_failed, g_skipped);
    return g_failed ? 1 : 0;
}
