// CrashSight SDK - public C++ API.
//
// Crash capture is best-effort. See docs/ for exactly what is collected and
// the limitations of in-process crash handling.
#pragma once

#include <cstddef>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace crashsight {

inline constexpr const char* kSdkVersion = "0.1.0";
inline constexpr int kSchemaVersion = 1;
inline constexpr std::size_t kMaxContextEntries = 32;
inline constexpr std::size_t kMaxContextKeyLength = 64;
inline constexpr std::size_t kMaxContextValueLength = 256;

struct Options {
    std::string application_name;
    std::string application_version;
    std::string environment = "development";
    std::string build_id;  // optional
    std::string local_output_directory = "./crash-reports";
};

struct Module {
    std::string name;      // path of the loaded object
    std::uint64_t base = 0;  // load address (ASLR-dependent)
    std::string build_id;  // GNU build-id (hex); empty when absent
};

struct Frame {
    std::uint64_t address = 0;        // raw instruction address (ASLR-dependent)
    std::string module;               // empty when unknown
    std::uint64_t module_offset = 0;  // address - module base; stable across runs
};

struct Report {
    int schema_version = kSchemaVersion;
    std::string report_id;
    std::string sdk_version = kSdkVersion;
    std::string kind;  // "fatal" or "diagnostic"
    std::string application_name;
    std::string application_version;
    std::string environment;
    std::string build_id;
    std::string os;
    std::string architecture;
    std::string timestamp_utc;  // ISO-8601
    std::string crash_type;     // e.g. "SIGSEGV" or "diagnostic"
    int signal_or_code = 0;
    std::uint64_t fault_address = 0;
    std::uint64_t process_id = 0;
    std::uint64_t thread_id = 0;
    std::string message;  // diagnostics only
    std::vector<Frame> frames;
    std::vector<Module> modules;
    std::map<std::string, std::string> context;
    std::string capture_method;
    std::string capture_limitations;
};

// Result codes. Zero is success.
enum class Status {
    Ok = 0,
    InvalidArgument,
    NotInitialized,
    AlreadyInitialized,
    IoError,
    ParseError,
    TooLarge,
};

const char* to_string(Status s) noexcept;

// Validates options; returns Ok or InvalidArgument.
Status validate(const Options& options) noexcept;

Status initialize(const Options& options) noexcept;
Status shutdown() noexcept;
bool is_initialized() noexcept;

// Bounded custom context. Oversized keys/values are truncated; entries past
// kMaxContextEntries are rejected with TooLarge.
Status set_context(const std::string& key, const std::string& value) noexcept;

// Nonfatal diagnostic event; written as a report file with kind="diagnostic".
// Never called from a crash handler.
Status report_diagnostic(const std::string& message, std::string* out_path = nullptr) noexcept;

// Converts raw crash records left by a previous crashed run (written by the
// signal handler) into JSON reports. Runs in normal context. Called
// automatically by initialize(); exposed for tools and tests.
Status finalize_pending_crashes(const std::string& directory,
                                std::vector<std::string>* out_paths = nullptr) noexcept;

// Serialization (stable JSON, schema v1).
std::string to_json(const Report& report);
Status from_json(const std::string& text, Report* out) noexcept;

// Unique report id (random 128-bit, hex with dashes).
std::string generate_report_id();

// RAII helper: initialize in constructor, shutdown in destructor.
class Session {
public:
    explicit Session(const Options& options) : status_(initialize(options)) {}
    ~Session() {
        if (status_ == Status::Ok) shutdown();
    }
    Session(const Session&) = delete;
    Session& operator=(const Session&) = delete;
    Status status() const noexcept { return status_; }

private:
    Status status_;
};

}  // namespace crashsight
