// Internal SDK interfaces. Not part of the public API.
#pragma once
#include <string>

#include "crashsight/crashsight.hpp"

namespace crashsight::internal {

Report base_report(const char* kind);
std::string output_directory();
Status write_report_file(const Report& r, std::string* out_path);

// Platform adapter (platform_posix.cpp). Only the POSIX/Linux adapter exists.
Status install_crash_handler(const Options& options);
void uninstall_crash_handler();

}  // namespace crashsight::internal
