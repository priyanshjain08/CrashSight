// Serialization/parsing micro-benchmark. Build in Release; results are only meaningful
// for the machine they were run on (see docs/development/testing.md).
#include <chrono>
#include <cstdio>

#include "crashsight/crashsight.hpp"

using clk = std::chrono::steady_clock;

int main() {
    crashsight::Report r;
    r.report_id = crashsight::generate_report_id();
    r.kind = "fatal";
    r.application_name = "Bench";
    r.application_version = "1.0";
    r.crash_type = "SIGSEGV";
    for (int i = 0; i < 32; ++i) r.frames.push_back({0x400000u + i * 16u, "/usr/bin/bench", 0x1000u + i * 16u});
    for (int i = 0; i < 20; ++i) r.modules.push_back({"/lib/libx" + std::to_string(i) + ".so", 0x7f0000u + i, "0123456789abcdef"});
    for (int i = 0; i < 16; ++i) r.context["k" + std::to_string(i)] = "value";
    const std::string text = crashsight::to_json(r);

    const int n = 20000;
    auto t0 = clk::now();
    std::size_t bytes = 0;
    for (int i = 0; i < n; ++i) bytes += crashsight::to_json(r).size();
    auto t1 = clk::now();
    crashsight::Report out;
    for (int i = 0; i < n; ++i) (void)crashsight::from_json(text, &out);
    auto t2 = clk::now();
    auto us = [](auto a, auto b) { return std::chrono::duration<double, std::micro>(b - a).count(); };
    std::printf("report size: %zu bytes (32 frames, 20 modules, 16 context entries)\n", text.size());
    std::printf("to_json  : %.2f us/op (%zu bytes total)\n", us(t0, t1) / n, bytes);
    std::printf("from_json: %.2f us/op\n", us(t1, t2) / n);
}
