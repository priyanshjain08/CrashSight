/* CrashSight C API sample. Normal startup never crashes.
 * Controlled crash (LOCAL TESTING ONLY, opt-in): basic_c_app --crash */
#include <signal.h>
#include <stdio.h>
#include <string.h>

#include "crashsight/crashsight.h"

__attribute__((noinline)) static void c_fault(void) { raise(SIGABRT); }

int main(int argc, char** argv) {
    int crash = 0;
    const char* dir = "./crash-reports";
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--crash") == 0) crash = 1;
        else if (strncmp(argv[i], "--out=", 6) == 0) dir = argv[i] + 6;
    }
    cs_options o = {"BasicCApp", "1.0.0", "development", "sample-build", dir};
    int rc = cs_initialize(&o);
    if (rc != 0) { fprintf(stderr, "init failed: %s\n", cs_status_string(rc)); return 2; }
    cs_set_context("language", "c");
    char path[512];
    if (cs_report_diagnostic("C sample started", path, sizeof path) == 0) printf("diagnostic written: %s\n", path);
    if (crash) { printf("LOCAL TESTING ONLY: triggering controlled abort\n"); c_fault(); }
    printf("normal run complete\n");
    cs_shutdown();
    return 0;
}
