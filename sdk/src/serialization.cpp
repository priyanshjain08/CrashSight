// Minimal JSON writer/parser for the CrashSight report schema (v1).
// The parser is intentionally strict and bounded: depth and size limits,
// no recursion beyond kMaxDepth, unknown fields are ignored.
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "crashsight/crashsight.hpp"

namespace crashsight {
namespace {

constexpr std::size_t kMaxReportBytes = 1u << 20;  // 1 MiB
constexpr int kMaxDepth = 16;

void append_escaped(std::string& out, const std::string& s) {
    out.push_back('"');
    for (unsigned char c : s) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (c < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof buf, "\\u%04x", c);
                    out += buf;
                } else {
                    out.push_back(static_cast<char>(c));
                }
        }
    }
    out.push_back('"');
}

std::string hex_addr(std::uint64_t v) {
    char buf[24];
    std::snprintf(buf, sizeof buf, "0x%llx", static_cast<unsigned long long>(v));
    return buf;
}

// ---- parser ----
struct Value {
    enum Type { Null, Bool, Number, String, Array, Object } type = Null;
    bool b = false;
    double num = 0;
    std::string str;
    std::vector<Value> arr;
    std::vector<std::pair<std::string, Value>> obj;

    const Value* get(const char* key) const {
        for (const auto& kv : obj)
            if (kv.first == key) return &kv.second;
        return nullptr;
    }
};

class Parser {
public:
    explicit Parser(const std::string& s) : s_(s) {}
    bool parse(Value* out) {
        skip();
        if (!value(out, 0)) return false;
        skip();
        return pos_ == s_.size();
    }

private:
    const std::string& s_;
    std::size_t pos_ = 0;

    void skip() {
        while (pos_ < s_.size() && std::isspace(static_cast<unsigned char>(s_[pos_]))) ++pos_;
    }
    bool lit(const char* word) {
        std::size_t n = std::strlen(word);
        if (s_.compare(pos_, n, word) != 0) return false;
        pos_ += n;
        return true;
    }
    bool value(Value* v, int depth) {
        if (depth > kMaxDepth || pos_ >= s_.size()) return false;
        char c = s_[pos_];
        if (c == '{') return object(v, depth);
        if (c == '[') return array(v, depth);
        if (c == '"') { v->type = Value::String; return string(&v->str); }
        if (c == 't') { v->type = Value::Bool; v->b = true; return lit("true"); }
        if (c == 'f') { v->type = Value::Bool; v->b = false; return lit("false"); }
        if (c == 'n') { v->type = Value::Null; return lit("null"); }
        return number(v);
    }
    bool number(Value* v) {
        const char* start = s_.c_str() + pos_;
        char* end = nullptr;
        double d = std::strtod(start, &end);
        if (end == start) return false;
        v->type = Value::Number;
        v->num = d;
        pos_ += static_cast<std::size_t>(end - start);
        return true;
    }
    bool string(std::string* out) {
        ++pos_;  // opening quote
        out->clear();
        while (pos_ < s_.size()) {
            char c = s_[pos_++];
            if (c == '"') return true;
            if (c == '\\') {
                if (pos_ >= s_.size()) return false;
                char e = s_[pos_++];
                switch (e) {
                    case '"': out->push_back('"'); break;
                    case '\\': out->push_back('\\'); break;
                    case '/': out->push_back('/'); break;
                    case 'n': out->push_back('\n'); break;
                    case 'r': out->push_back('\r'); break;
                    case 't': out->push_back('\t'); break;
                    case 'b': out->push_back('\b'); break;
                    case 'f': out->push_back('\f'); break;
                    case 'u': {
                        if (pos_ + 4 > s_.size()) return false;
                        unsigned code = 0;
                        for (int i = 0; i < 4; ++i) {
                            char h = s_[pos_++];
                            code <<= 4;
                            if (h >= '0' && h <= '9') code |= static_cast<unsigned>(h - '0');
                            else if (h >= 'a' && h <= 'f') code |= static_cast<unsigned>(h - 'a' + 10);
                            else if (h >= 'A' && h <= 'F') code |= static_cast<unsigned>(h - 'A' + 10);
                            else return false;
                        }
                        // Only the BMP ASCII subset is round-tripped; others become '?'.
                        out->push_back(code < 0x80 ? static_cast<char>(code) : '?');
                        break;
                    }
                    default: return false;
                }
            } else if (static_cast<unsigned char>(c) < 0x20) {
                return false;
            } else {
                out->push_back(c);
            }
        }
        return false;
    }
    bool array(Value* v, int depth) {
        v->type = Value::Array;
        ++pos_;
        skip();
        if (pos_ < s_.size() && s_[pos_] == ']') { ++pos_; return true; }
        while (true) {
            Value item;
            skip();
            if (!value(&item, depth + 1)) return false;
            v->arr.push_back(std::move(item));
            skip();
            if (pos_ >= s_.size()) return false;
            if (s_[pos_] == ',') { ++pos_; continue; }
            if (s_[pos_] == ']') { ++pos_; return true; }
            return false;
        }
    }
    bool object(Value* v, int depth) {
        v->type = Value::Object;
        ++pos_;
        skip();
        if (pos_ < s_.size() && s_[pos_] == '}') { ++pos_; return true; }
        while (true) {
            skip();
            if (pos_ >= s_.size() || s_[pos_] != '"') return false;
            std::string key;
            if (!string(&key)) return false;
            skip();
            if (pos_ >= s_.size() || s_[pos_] != ':') return false;
            ++pos_;
            skip();
            Value item;
            if (!value(&item, depth + 1)) return false;
            v->obj.emplace_back(std::move(key), std::move(item));
            skip();
            if (pos_ >= s_.size()) return false;
            if (s_[pos_] == ',') { ++pos_; continue; }
            if (s_[pos_] == '}') { ++pos_; return true; }
            return false;
        }
    }
};

std::string str_field(const Value& o, const char* key) {
    const Value* v = o.get(key);
    return (v && v->type == Value::String) ? v->str : std::string();
}

std::uint64_t addr_field(const Value& o, const char* key) {
    const Value* v = o.get(key);
    if (!v) return 0;
    if (v->type == Value::String) return std::strtoull(v->str.c_str(), nullptr, 0);
    if (v->type == Value::Number && v->num >= 0) return static_cast<std::uint64_t>(v->num);
    return 0;
}

}  // namespace

std::string to_json(const Report& r) {
    std::string out;
    out.reserve(512 + r.frames.size() * 64);
    auto kv = [&](const char* k, const std::string& v, bool last = false) {
        out += "  ";
        append_escaped(out, k);
        out += ": ";
        append_escaped(out, v);
        out += last ? "\n" : ",\n";
    };
    out += "{\n";
    out += "  \"schema_version\": " + std::to_string(r.schema_version) + ",\n";
    kv("report_id", r.report_id);
    kv("sdk_version", r.sdk_version);
    kv("kind", r.kind);
    kv("application_name", r.application_name);
    kv("application_version", r.application_version);
    kv("environment", r.environment);
    kv("build_id", r.build_id);
    kv("os", r.os);
    kv("architecture", r.architecture);
    kv("timestamp_utc", r.timestamp_utc);
    kv("crash_type", r.crash_type);
    out += "  \"signal_or_code\": " + std::to_string(r.signal_or_code) + ",\n";
    kv("fault_address", hex_addr(r.fault_address));
    out += "  \"process_id\": " + std::to_string(r.process_id) + ",\n";
    out += "  \"thread_id\": " + std::to_string(r.thread_id) + ",\n";
    kv("message", r.message);
    out += "  \"frames\": [";
    for (std::size_t i = 0; i < r.frames.size(); ++i) {
        out += i ? ",\n    " : "\n    ";
        out += "{\"address\": ";
        append_escaped(out, hex_addr(r.frames[i].address));
        out += ", \"module\": ";
        append_escaped(out, r.frames[i].module);
        out += ", \"module_offset\": ";
        append_escaped(out, hex_addr(r.frames[i].module_offset));
        out += "}";
    }
    out += r.frames.empty() ? "],\n" : "\n  ],\n";
    out += "  \"modules\": [";
    for (std::size_t i = 0; i < r.modules.size(); ++i) {
        out += i ? ",\n    " : "\n    ";
        out += "{\"name\": ";
        append_escaped(out, r.modules[i].name);
        out += ", \"base\": ";
        append_escaped(out, hex_addr(r.modules[i].base));
        out += ", \"build_id\": ";
        append_escaped(out, r.modules[i].build_id);
        out += "}";
    }
    out += r.modules.empty() ? "],\n" : "\n  ],\n";
    out += "  \"context\": {";
    bool first = true;
    for (const auto& kvp : r.context) {
        out += first ? "\n    " : ",\n    ";
        first = false;
        append_escaped(out, kvp.first);
        out += ": ";
        append_escaped(out, kvp.second);
    }
    out += first ? "},\n" : "\n  },\n";
    kv("capture_method", r.capture_method);
    kv("capture_limitations", r.capture_limitations, true);
    out += "}\n";
    return out;
}

Status from_json(const std::string& text, Report* out) noexcept {
    if (!out) return Status::InvalidArgument;
    if (text.size() > kMaxReportBytes) return Status::TooLarge;
    try {
        Value root;
        Parser p(text);
        if (!p.parse(&root) || root.type != Value::Object) return Status::ParseError;

        const Value* ver = root.get("schema_version");
        if (!ver || ver->type != Value::Number) return Status::ParseError;
        int version = static_cast<int>(ver->num);
        // Compatibility: v1 is current. Newer majors are rejected; unknown
        // fields within a known major are ignored.
        if (version < 1 || version > kSchemaVersion) return Status::ParseError;

        Report r;
        r.schema_version = version;
        r.report_id = str_field(root, "report_id");
        if (r.report_id.empty()) return Status::ParseError;
        r.sdk_version = str_field(root, "sdk_version");
        r.kind = str_field(root, "kind");
        r.application_name = str_field(root, "application_name");
        r.application_version = str_field(root, "application_version");
        r.environment = str_field(root, "environment");
        r.build_id = str_field(root, "build_id");
        r.os = str_field(root, "os");
        r.architecture = str_field(root, "architecture");
        r.timestamp_utc = str_field(root, "timestamp_utc");
        r.crash_type = str_field(root, "crash_type");
        if (const Value* v = root.get("signal_or_code"); v && v->type == Value::Number)
            r.signal_or_code = static_cast<int>(v->num);
        r.fault_address = addr_field(root, "fault_address");
        r.process_id = addr_field(root, "process_id");
        r.thread_id = addr_field(root, "thread_id");
        r.message = str_field(root, "message");
        r.capture_method = str_field(root, "capture_method");
        r.capture_limitations = str_field(root, "capture_limitations");

        if (const Value* fr = root.get("frames"); fr && fr->type == Value::Array) {
            for (const Value& f : fr->arr) {
                if (f.type != Value::Object) return Status::ParseError;
                Frame frame;
                frame.address = addr_field(f, "address");
                frame.module = str_field(f, "module");
                frame.module_offset = addr_field(f, "module_offset");
                r.frames.push_back(std::move(frame));
            }
        }
        if (const Value* md = root.get("modules"); md && md->type == Value::Array) {
            for (const Value& m : md->arr) {
                if (m.type != Value::Object) return Status::ParseError;
                Module mod;
                mod.name = str_field(m, "name");
                mod.base = addr_field(m, "base");
                mod.build_id = str_field(m, "build_id");
                r.modules.push_back(std::move(mod));
            }
        }
        if (const Value* cx = root.get("context"); cx && cx->type == Value::Object) {
            for (const auto& kvp : cx->obj)
                if (kvp.second.type == Value::String) r.context[kvp.first] = kvp.second.str;
        }
        *out = std::move(r);
        return Status::Ok;
    } catch (...) {
        return Status::ParseError;
    }
}

}  // namespace crashsight
