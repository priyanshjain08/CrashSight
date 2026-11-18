#include "crashsight/crashsight.hpp"

#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <fstream>
#include <mutex>
#include <random>

#include "crashsight/crashsight.h"
#include "internal.hpp"

namespace crashsight {
namespace {

struct State {
    std::mutex mutex;
    bool initialized = false;
    Options options;
    std::map<std::string, std::string> context;
};

State& state() {
    static State s;
    return s;
}

std::string utc_now() {
    std::time_t t = std::time(nullptr);
    std::tm tm{};
    gmtime_r(&t, &tm);
    char buf[32];
    std::strftime(buf, sizeof buf, "%Y-%m-%dT%H:%M:%SZ", &tm);
    return buf;
}

bool safe_name(const std::string& s) { return s.find('\0') == std::string::npos; }

bool ensure_directory(const std::string& dir) {
    struct stat st{};
    if (::stat(dir.c_str(), &st) == 0) return S_ISDIR(st.st_mode);
    // Create one level (and parents) manually; no shell involved.
    std::string path;
    for (std::size_t i = 0; i <= dir.size(); ++i) {
        if (i == dir.size() || dir[i] == '/') {
            if (!path.empty() && ::mkdir(path.c_str(), 0700) != 0 && errno != EEXIST) return false;
        }
        if (i < dir.size()) path.push_back(dir[i]);
    }
    return ::stat(dir.c_str(), &st) == 0 && S_ISDIR(st.st_mode);
}

}  // namespace

const char* to_string(Status s) noexcept {
    switch (s) {
        case Status::Ok: return "ok";
        case Status::InvalidArgument: return "invalid argument";
        case Status::NotInitialized: return "not initialized";
        case Status::AlreadyInitialized: return "already initialized";
        case Status::IoError: return "I/O error";
        case Status::ParseError: return "parse error";
        case Status::TooLarge: return "too large";
    }
    return "unknown";
}

Status validate(const Options& o) noexcept {
    if (o.application_name.empty() || o.application_version.empty()) return Status::InvalidArgument;
    if (o.local_output_directory.empty()) return Status::InvalidArgument;
    if (o.application_name.size() > 128 || o.application_version.size() > 64 ||
        o.environment.size() > 64 || o.build_id.size() > 128)
        return Status::InvalidArgument;
    if (!safe_name(o.local_output_directory)) return Status::InvalidArgument;
    return Status::Ok;
}

std::string generate_report_id() {
    thread_local std::random_device rd;
    unsigned char b[16];
    for (int i = 0; i < 4; ++i) {
        unsigned v = rd();
        std::memcpy(b + i * 4, &v, 4);
    }
    b[6] = static_cast<unsigned char>((b[6] & 0x0f) | 0x40);  // version 4
    b[8] = static_cast<unsigned char>((b[8] & 0x3f) | 0x80);
    char buf[40];
    std::snprintf(buf, sizeof buf,
                  "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                  b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11],
                  b[12], b[13], b[14], b[15]);
    return buf;
}

Status initialize(const Options& options) noexcept {
    try {
        Status v = validate(options);
        if (v != Status::Ok) return v;
        State& s = state();
        {
            std::lock_guard<std::mutex> lock(s.mutex);
            if (s.initialized) return Status::AlreadyInitialized;
            if (!ensure_directory(options.local_output_directory)) return Status::IoError;
            s.options = options;
            s.context.clear();
            Status p = internal::install_crash_handler(options);
            if (p != Status::Ok) return p;
            s.initialized = true;
        }
        // Outside the lock: convert raw records left by earlier crashed runs.
        finalize_pending_crashes(options.local_output_directory, nullptr);
        return Status::Ok;
    } catch (...) {
        return Status::IoError;
    }
}

Status shutdown() noexcept {
    State& s = state();
    std::lock_guard<std::mutex> lock(s.mutex);
    if (!s.initialized) return Status::NotInitialized;
    internal::uninstall_crash_handler();
    s.initialized = false;
    s.context.clear();
    return Status::Ok;
}

bool is_initialized() noexcept {
    State& s = state();
    std::lock_guard<std::mutex> lock(s.mutex);
    return s.initialized;
}

Status set_context(const std::string& key, const std::string& value) noexcept {
    try {
        if (key.empty()) return Status::InvalidArgument;
        State& s = state();
        std::lock_guard<std::mutex> lock(s.mutex);
        if (!s.initialized) return Status::NotInitialized;
        std::string k = key.substr(0, kMaxContextKeyLength);
        std::string val = value.substr(0, kMaxContextValueLength);
        if (s.context.find(k) == s.context.end() && s.context.size() >= kMaxContextEntries)
            return Status::TooLarge;
        s.context[k] = val;
        return Status::Ok;
    } catch (...) {
        return Status::IoError;
    }
}

namespace internal {

Report base_report(const char* kind) {
    State& s = state();
    Report r;
    r.report_id = generate_report_id();
    r.kind = kind;
    r.timestamp_utc = utc_now();
    r.os = "linux";
#if defined(__x86_64__)
    r.architecture = "x86_64";
#elif defined(__aarch64__)
    r.architecture = "aarch64";
#else
    r.architecture = "unknown";
#endif
    r.process_id = static_cast<std::uint64_t>(::getpid());
    std::lock_guard<std::mutex> lock(s.mutex);
    r.application_name = s.options.application_name;
    r.application_version = s.options.application_version;
    r.environment = s.options.environment;
    r.build_id = s.options.build_id;
    r.context = s.context;
    return r;
}

std::string output_directory() {
    State& s = state();
    std::lock_guard<std::mutex> lock(s.mutex);
    return s.options.local_output_directory;
}

// Atomic write: write to a temp file in the same directory, fsync, rename.
Status write_report_file(const Report& r, std::string* out_path) {
    std::string dir = output_directory();
    std::string final_path = dir + "/" + r.report_id + ".json";
    std::string tmp_path = final_path + ".tmp";
    std::string body = to_json(r);
    {
        std::ofstream f(tmp_path, std::ios::binary | std::ios::trunc);
        if (!f) return Status::IoError;
        f.write(body.data(), static_cast<std::streamsize>(body.size()));
        f.flush();
        if (!f) {
            f.close();
            std::remove(tmp_path.c_str());
            return Status::IoError;
        }
    }
    if (std::rename(tmp_path.c_str(), final_path.c_str()) != 0) {
        std::remove(tmp_path.c_str());
        return Status::IoError;
    }
    if (out_path) *out_path = final_path;
    return Status::Ok;
}

}  // namespace internal

Status report_diagnostic(const std::string& message, std::string* out_path) noexcept {
    try {
        if (!is_initialized()) return Status::NotInitialized;
        Report r = internal::base_report("diagnostic");
        r.crash_type = "diagnostic";
        r.message = message.substr(0, 1024);
        r.capture_method = "manual";
        r.capture_limitations = "Manual diagnostic event; no stack captured.";
        return internal::write_report_file(r, out_path);
    } catch (...) {
        return Status::IoError;
    }
}

}  // namespace crashsight

// ---------------------------------------------------------------- C API
extern "C" {

int cs_initialize(const cs_options* o) {
    if (!o) return static_cast<int>(crashsight::Status::InvalidArgument);
    crashsight::Options opts;
    opts.application_name = o->application_name ? o->application_name : "";
    opts.application_version = o->application_version ? o->application_version : "";
    if (o->environment) opts.environment = o->environment;
    if (o->build_id) opts.build_id = o->build_id;
    if (o->output_directory) opts.local_output_directory = o->output_directory;
    return static_cast<int>(crashsight::initialize(opts));
}

int cs_shutdown(void) { return static_cast<int>(crashsight::shutdown()); }

int cs_set_context(const char* key, const char* value) {
    if (!key || !value) return static_cast<int>(crashsight::Status::InvalidArgument);
    return static_cast<int>(crashsight::set_context(key, value));
}

int cs_report_diagnostic(const char* message, char* out_path, unsigned long out_path_size) {
    if (!message) return static_cast<int>(crashsight::Status::InvalidArgument);
    std::string path;
    crashsight::Status s = crashsight::report_diagnostic(message, out_path ? &path : nullptr);
    if (s == crashsight::Status::Ok && out_path && out_path_size > 0) {
        std::strncpy(out_path, path.c_str(), out_path_size - 1);
        out_path[out_path_size - 1] = '\0';
    }
    return static_cast<int>(s);
}

const char* cs_status_string(int status) {
    return crashsight::to_string(static_cast<crashsight::Status>(status));
}

}  // extern "C"
