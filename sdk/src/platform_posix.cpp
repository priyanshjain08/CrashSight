// POSIX/Linux crash-capture adapter.
//
// SIGNAL HANDLER RULES (see docs/security/privacy.md and docs/crash-report-format):
//  * The handler only calls open/write/close/_exit/getpid/syscall/sigaction/raise
//    plus glibc backtrace() (see limitation below) and does its own integer
//    formatting into static buffers. No malloc, no stdio, no mutexes, no JSON.
//  * Everything it needs (output path, module table) is prepared at init time.
//  * It writes a small fixed-format "raw record" (.csraw). Conversion to the JSON
//    report happens later in finalize_pending_crashes(), in normal context.
//  * Prior handlers are saved and chained. An alternate stack is installed.
//
// KNOWN LIMITATIONS: backtrace() is not formally async-signal-safe; it is primed
// at init so libgcc is already loaded, which avoids the usual malloc. Heap
// corruption, stack exhaustion beyond the alt stack, and SIGKILL are not covered.
// Modules loaded with dlopen() after init are not in the module table.
#include <dirent.h>
#include <elf.h>
#include <execinfo.h>
#include <fcntl.h>
#include <link.h>
#include <signal.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fstream>
#include <sstream>

#include "internal.hpp"

namespace crashsight::internal {
namespace {

constexpr int kMaxFrames = 64;
constexpr int kMaxModules = 128;
constexpr int kSignals[] = {SIGSEGV, SIGABRT, SIGFPE, SIGILL, SIGBUS};
constexpr int kNumSignals = sizeof(kSignals) / sizeof(kSignals[0]);

struct ModuleInfo {
    char name[256];
    unsigned long base;
    char build_id[65];
};

// Static storage so the handler never allocates.
char g_path[512];
// Pre-formatted identity of the running process (single line each; no newlines).
char g_meta_app[130], g_meta_version[66], g_meta_env[66], g_meta_build[130];

void copy_line(char* dst, size_t cap, const std::string& src) {
    size_t n = 0;
    for (; n + 1 < cap && n < src.size(); ++n) dst[n] = (src[n] == '\n' || src[n] == '\r') ? ' ' : src[n];
    dst[n] = '\0';
}
ModuleInfo g_modules[kMaxModules];
int g_module_count = 0;
struct sigaction g_old[kNumSignals];
void* g_alt_stack = nullptr;
bool g_installed = false;

int signal_index(int sig) {
    for (int i = 0; i < kNumSignals; ++i)
        if (kSignals[i] == sig) return i;
    return -1;
}

// ---- async-signal-safe helpers ----
void put(int fd, const char* s) {
    size_t n = 0;
    while (s[n]) ++n;
    while (n > 0) {
        ssize_t w = ::write(fd, s, n);
        if (w <= 0) return;
        s += w;
        n -= static_cast<size_t>(w);
    }
}

void put_hex(int fd, unsigned long v) {
    char buf[19];
    buf[18] = '\0';
    int i = 18;
    do {
        buf[--i] = "0123456789abcdef"[v & 0xf];
        v >>= 4;
    } while (v && i > 2);
    buf[--i] = 'x';
    buf[--i] = '0';
    put(fd, buf + i);
}

void put_dec(int fd, long v) {
    char buf[24];
    int i = 23;
    buf[23] = '\0';
    bool neg = v < 0;
    unsigned long u = neg ? static_cast<unsigned long>(-v) : static_cast<unsigned long>(v);
    do {
        buf[--i] = static_cast<char>('0' + u % 10);
        u /= 10;
    } while (u);
    if (neg) buf[--i] = '-';
    put(fd, buf + i);
}

void handler(int sig, siginfo_t* info, void* ctx) {
    int fd = ::open(g_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd >= 0) {
        put(fd, "CSRAW1\n");
        put(fd, "app="); put(fd, g_meta_app); put(fd, "\n");
        put(fd, "version="); put(fd, g_meta_version); put(fd, "\n");
        put(fd, "env="); put(fd, g_meta_env); put(fd, "\n");
        put(fd, "build="); put(fd, g_meta_build); put(fd, "\n");
        put(fd, "time="); put_dec(fd, static_cast<long>(::time(nullptr))); put(fd, "\n");
        put(fd, "signal="); put_dec(fd, sig); put(fd, "\n");
        put(fd, "code="); put_dec(fd, info ? info->si_code : 0); put(fd, "\n");
        put(fd, "fault="); put_hex(fd, info ? reinterpret_cast<unsigned long>(info->si_addr) : 0); put(fd, "\n");
        put(fd, "pid="); put_dec(fd, ::getpid()); put(fd, "\n");
        put(fd, "tid="); put_dec(fd, ::syscall(SYS_gettid)); put(fd, "\n");
        for (int i = 0; i < g_module_count; ++i) {
            put(fd, "module="); put_hex(fd, g_modules[i].base);
            put(fd, " "); put(fd, g_modules[i].build_id[0] ? g_modules[i].build_id : "-");
            put(fd, " "); put(fd, g_modules[i].name); put(fd, "\n");
        }
        void* frames[kMaxFrames];
        int n = ::backtrace(frames, kMaxFrames);
        for (int i = 0; i < n; ++i) {
            put(fd, "frame="); put_hex(fd, reinterpret_cast<unsigned long>(frames[i])); put(fd, "\n");
        }
        put(fd, "end\n");
        ::close(fd);
    }
    (void)ctx;
    // Chain to the previous handler if one existed, else restore default and re-raise.
    int idx = signal_index(sig);
    if (idx >= 0 && (g_old[idx].sa_flags & SA_SIGINFO) && g_old[idx].sa_sigaction) {
        g_old[idx].sa_sigaction(sig, info, ctx);
    } else if (idx >= 0 && g_old[idx].sa_handler != SIG_DFL && g_old[idx].sa_handler != SIG_IGN &&
               !(g_old[idx].sa_flags & SA_SIGINFO)) {
        g_old[idx].sa_handler(sig);
    }
    struct sigaction dfl;
    std::memset(&dfl, 0, sizeof dfl);
    dfl.sa_handler = SIG_DFL;
    ::sigaction(sig, &dfl, nullptr);
    // Return: the signal is blocked inside the handler, so the re-raised (or
    // original synchronous) signal is delivered with the default action as soon as
    // the handler returns, preserving the normal "killed by signal" exit status.
    ::raise(sig);
}

// Parse the GNU build-id note out of a loaded object's program headers.
void read_build_id(const dl_phdr_info* info, char* out, size_t cap) {
    out[0] = '\0';
    for (int i = 0; i < info->dlpi_phnum; ++i) {
        const ElfW(Phdr)& ph = info->dlpi_phdr[i];
        if (ph.p_type != PT_NOTE) continue;
        const unsigned char* p = reinterpret_cast<const unsigned char*>(info->dlpi_addr + ph.p_vaddr);
        const unsigned char* end = p + ph.p_memsz;
        while (p + sizeof(ElfW(Nhdr)) <= end) {
            const ElfW(Nhdr)* nh = reinterpret_cast<const ElfW(Nhdr)*>(p);
            const unsigned char* name = p + sizeof(ElfW(Nhdr));
            const unsigned char* desc = name + ((nh->n_namesz + 3) & ~3u);
            const unsigned char* next = desc + ((nh->n_descsz + 3) & ~3u);
            if (next > end) break;
            if (nh->n_type == NT_GNU_BUILD_ID && nh->n_namesz == 4 && std::memcmp(name, "GNU", 3) == 0) {
                size_t o = 0;
                for (unsigned j = 0; j < nh->n_descsz && o + 2 < cap; ++j) {
                    out[o++] = "0123456789abcdef"[desc[j] >> 4];
                    out[o++] = "0123456789abcdef"[desc[j] & 0xf];
                }
                out[o] = '\0';
                return;
            }
            p = next;
        }
    }
}

int collect_module(dl_phdr_info* info, size_t, void*) {
    if (g_module_count >= kMaxModules) return 1;
    ModuleInfo& m = g_modules[g_module_count];
    const char* name = (info->dlpi_name && info->dlpi_name[0]) ? info->dlpi_name : "/proc/self/exe";
    if (name[0] == '/' && std::strcmp(name, "/proc/self/exe") == 0) {
        ssize_t n = ::readlink("/proc/self/exe", m.name, sizeof m.name - 1);
        if (n > 0) m.name[n] = '\0'; else std::strncpy(m.name, name, sizeof m.name - 1);
    } else {
        std::strncpy(m.name, name, sizeof m.name - 1);
        m.name[sizeof m.name - 1] = '\0';
    }
    m.base = info->dlpi_addr;
    read_build_id(info, m.build_id, sizeof m.build_id);
    ++g_module_count;
    return 0;
}

}  // namespace

Status install_crash_handler(const Options& options) {
    if (g_installed) return Status::AlreadyInitialized;
    std::string dir = options.local_output_directory;
    std::string path = dir + "/pending-" + std::to_string(::getpid()) + ".csraw";
    if (path.size() >= sizeof g_path) return Status::InvalidArgument;
    std::strcpy(g_path, path.c_str());
    copy_line(g_meta_app, sizeof g_meta_app, options.application_name);
    copy_line(g_meta_version, sizeof g_meta_version, options.application_version);
    copy_line(g_meta_env, sizeof g_meta_env, options.environment);
    copy_line(g_meta_build, sizeof g_meta_build, options.build_id);

    g_module_count = 0;
    ::dl_iterate_phdr(collect_module, nullptr);

    void* prime[4];
    ::backtrace(prime, 4);  // loads libgcc now so the handler does not allocate

    const size_t stack_size = 64 * 1024;
    g_alt_stack = std::malloc(stack_size);
    if (!g_alt_stack) return Status::IoError;
    stack_t ss{};
    ss.ss_sp = g_alt_stack;
    ss.ss_size = stack_size;
    if (::sigaltstack(&ss, nullptr) != 0) {
        std::free(g_alt_stack);
        g_alt_stack = nullptr;
        return Status::IoError;
    }

    struct sigaction sa;
    std::memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = handler;
    sa.sa_flags = SA_SIGINFO | SA_ONSTACK | SA_RESETHAND;
    ::sigemptyset(&sa.sa_mask);
    for (int i = 0; i < kNumSignals; ++i) ::sigaction(kSignals[i], &sa, &g_old[i]);
    g_installed = true;
    return Status::Ok;
}

void uninstall_crash_handler() {
    if (!g_installed) return;
    for (int i = 0; i < kNumSignals; ++i) ::sigaction(kSignals[i], &g_old[i], nullptr);
    stack_t ss{};
    ss.ss_flags = SS_DISABLE;
    ::sigaltstack(&ss, nullptr);
    std::free(g_alt_stack);
    g_alt_stack = nullptr;
    g_installed = false;
}

}  // namespace crashsight::internal

namespace crashsight {

Status finalize_pending_crashes(const std::string& directory,
                                std::vector<std::string>* out_paths) noexcept {
    try {
        DIR* d = ::opendir(directory.c_str());
        if (!d) return Status::IoError;
        std::vector<std::string> raws;
        while (dirent* e = ::readdir(d)) {
            std::string n = e->d_name;
            if (n.size() > 6 && n.compare(n.size() - 6, 6, ".csraw") == 0) raws.push_back(n);
        }
        ::closedir(d);

        for (const std::string& name : raws) {
            std::string path = directory + "/" + name;
            std::ifstream in(path);
            std::string line;
            if (!std::getline(in, line) || line != "CSRAW1") { std::remove(path.c_str()); continue; }

            Report r = internal::base_report("fatal");
            // Identity comes from the crashed process, not from whoever finalizes.
            r.application_name.clear();
            r.application_version.clear();
            r.environment.clear();
            r.build_id.clear();
            r.context.clear();
            unsigned long long sig = 0, fault = 0, pid = 0, tid = 0;
            bool complete = false;
            std::vector<unsigned long long> addrs;
            while (std::getline(in, line)) {
                auto val = [&](const char* key) -> const char* {
                    size_t n = std::strlen(key);
                    return line.compare(0, n, key) == 0 ? line.c_str() + n : nullptr;
                };
                if (const char* a = val("app=")) r.application_name = a;
                else if (const char* a2 = val("version=")) r.application_version = a2;
                else if (const char* a3 = val("env=")) r.environment = a3;
                else if (const char* a4 = val("build=")) r.build_id = a4;
                else if (const char* a5 = val("time=")) {
                    std::time_t t = static_cast<std::time_t>(std::strtoll(a5, nullptr, 10));
                    std::tm tmv{};
                    gmtime_r(&t, &tmv);
                    char tb[32];
                    std::strftime(tb, sizeof tb, "%Y-%m-%dT%H:%M:%SZ", &tmv);
                    r.timestamp_utc = tb;
                }
                else if (const char* v = val("signal=")) sig = std::strtoull(v, nullptr, 10);
                else if (const char* v2 = val("fault=")) fault = std::strtoull(v2, nullptr, 16);
                else if (const char* v3 = val("pid=")) pid = std::strtoull(v3, nullptr, 10);
                else if (const char* v4 = val("tid=")) tid = std::strtoull(v4, nullptr, 10);
                else if (const char* v5 = val("module=")) {
                    std::istringstream ss(v5);
                    std::string base, bid, mname;
                    ss >> base >> bid;
                    std::getline(ss >> std::ws, mname);
                    Module m;
                    m.base = std::strtoull(base.c_str(), nullptr, 16);
                    m.build_id = (bid == "-") ? "" : bid;
                    m.name = mname;
                    r.modules.push_back(m);
                } else if (const char* v6 = val("frame=")) addrs.push_back(std::strtoull(v6, nullptr, 16));
                else if (line == "end") complete = true;
            }
            in.close();

            const char* sname = sig == SIGSEGV ? "SIGSEGV" : sig == SIGABRT ? "SIGABRT" :
                                sig == SIGFPE ? "SIGFPE" : sig == SIGILL ? "SIGILL" :
                                sig == SIGBUS ? "SIGBUS" : "SIGNAL";
            r.crash_type = sname;
            r.signal_or_code = static_cast<int>(sig);
            r.fault_address = fault;
            r.process_id = pid;
            r.thread_id = tid;
            r.capture_method = "posix-signal-handler";
            r.capture_limitations = complete
                ? "Minimal async-signal-safe record; stack via glibc backtrace(); modules loaded after init are not listed."
                : "Raw record was truncated (handler interrupted); stack may be incomplete.";

            // backtrace() is called inside the handler, so the first two entries are
            // always [our handler, libc signal trampoline]. Drop them so frame 0 is the
            // crash PC. (glibc/x86_64 behaviour; documented limitation.)
            if (addrs.size() > 2) addrs.erase(addrs.begin(), addrs.begin() + 2);

            // Attribute each frame to the module with the greatest base <= address.
            for (unsigned long long a : addrs) {
                Frame f;
                f.address = a;
                const Module* best = nullptr;
                for (const Module& m : r.modules)
                    if (m.base <= a && (!best || m.base > best->base)) best = &m;
                if (best) { f.module = best->name; f.module_offset = a - best->base; }
                r.frames.push_back(f);
            }
            std::string out;
            if (internal::write_report_file(r, &out) == Status::Ok) {
                std::remove(path.c_str());
                if (out_paths) out_paths->push_back(out);
            }
        }
        return Status::Ok;
    } catch (...) {
        return Status::IoError;
    }
}

}  // namespace crashsight
