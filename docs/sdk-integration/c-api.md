# C API

Header: `crashsight/crashsight.h`. All functions return `0` on success; `cs_status_string(rc)` describes errors.
```c
cs_options o = {"MyApp", "1.0.0", "production", "ci-1234", "./crash-reports"};
int rc = cs_initialize(&o);            /* NULL environment/output_directory use defaults */
cs_set_context("mode", "batch");
char path[512]; cs_report_diagnostic("disk low", path, sizeof path);
cs_shutdown();
```
The library is C++ internally: link a C program with `g++` or add `-lstdc++`. Sample: `examples/basic-c-app/main.c`.
