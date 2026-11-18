/* CrashSight SDK - C API. Thin wrapper over the C++ implementation. */
#ifndef CRASHSIGHT_H
#define CRASHSIGHT_H

#ifdef __cplusplus
extern "C" {
#endif

typedef struct cs_options {
    const char* application_name;
    const char* application_version;
    const char* environment;   /* NULL -> "development" */
    const char* build_id;      /* optional, may be NULL */
    const char* output_directory; /* NULL -> "./crash-reports" */
} cs_options;

/* Return codes: 0 = success; see crashsight::Status for the others. */
int cs_initialize(const cs_options* options);
int cs_shutdown(void);
int cs_set_context(const char* key, const char* value);
/* out_path may be NULL; otherwise receives a NUL-terminated path. */
int cs_report_diagnostic(const char* message, char* out_path, unsigned long out_path_size);
const char* cs_status_string(int status);

#ifdef __cplusplus
}
#endif

#endif /* CRASHSIGHT_H */
