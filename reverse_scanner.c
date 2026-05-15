#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <wchar.h>
#include <wctype.h>

#define MAGIC "DS3200807"
#define NOTICE "This document is protected by ShadowCube Tech. & Policies."
#define HEADER_READ_BYTES 128
#define DEFAULT_LOG_EVERY 10000ULL

typedef enum ScanStatus {
    STATUS_CLEAR,
    STATUS_ENCRYPTED,
    STATUS_SUSPECT,
    STATUS_ERROR
} ScanStatus;

typedef struct Options {
    int loose;
    int follow_links;
    int fail_if_found;
    int no_color;
    int report_all;
    unsigned long long log_every;
    ULONGLONG started_ms;
    const wchar_t *report_path;
    const wchar_t *move_path;
    wchar_t *move_root_abs;
    const wchar_t **paths;
    int path_count;
} Options;

typedef struct Counters {
    unsigned long long scanned;
    unsigned long long encrypted;
    unsigned long long suspect;
    unsigned long long clear;
    unsigned long long errors;
    unsigned long long move_success;
    unsigned long long move_failed;
} Counters;

typedef struct ReportWriter {
    FILE *file;
    int enabled;
} ReportWriter;

typedef struct PathStack {
    wchar_t **items;
    size_t count;
    size_t capacity;
} PathStack;

typedef struct MoveOutcome {
    int attempted;
    int success;
    wchar_t *destination;
    wchar_t *error;
} MoveOutcome;

static HANDLE stdout_handle;
static int stdout_is_console;
static int color_enabled = 1;
static WORD default_console_attributes;

static wchar_t *windows_error_message(DWORD code);

static void *xmalloc(size_t size) {
    void *ptr = malloc(size ? size : 1);
    if (!ptr) {
        fwprintf(stderr, L"Out of memory\n");
        exit(2);
    }
    return ptr;
}

static wchar_t *xwcsdup(const wchar_t *value) {
    size_t len = wcslen(value);
    wchar_t *copy = (wchar_t *)xmalloc((len + 1) * sizeof(wchar_t));
    wcscpy(copy, value);
    return copy;
}

static void normalize_slashes(wchar_t *path) {
    for (wchar_t *cursor = path; *cursor; cursor++) {
        if (*cursor == L'/') {
            *cursor = L'\\';
        }
    }
}

static int has_prefix(const wchar_t *value, const wchar_t *prefix) {
    return wcsncmp(value, prefix, wcslen(prefix)) == 0;
}

static int is_drive_absolute(const wchar_t *path) {
    return ((path[0] >= L'A' && path[0] <= L'Z') || (path[0] >= L'a' && path[0] <= L'z')) &&
           path[1] == L':' &&
           (path[2] == L'\\' || path[2] == L'/');
}

static int is_unc_path(const wchar_t *path) {
    return has_prefix(path, L"\\\\") && !has_prefix(path, L"\\\\?\\") && !has_prefix(path, L"\\\\.\\");
}

static wchar_t *prefix_extended_path(wchar_t *absolute_path) {
    normalize_slashes(absolute_path);

    if (has_prefix(absolute_path, L"\\\\?\\") || has_prefix(absolute_path, L"\\\\.\\")) {
        return xwcsdup(absolute_path);
    }

    if (is_unc_path(absolute_path)) {
        const wchar_t *without_slashes = absolute_path + 2;
        const wchar_t *prefix = L"\\\\?\\UNC\\";
        size_t len = wcslen(prefix) + wcslen(without_slashes);
        wchar_t *extended = (wchar_t *)xmalloc((len + 1) * sizeof(wchar_t));
        wcscpy(extended, prefix);
        wcscat(extended, without_slashes);
        return extended;
    }

    {
        const wchar_t *prefix = L"\\\\?\\";
        size_t len = wcslen(prefix) + wcslen(absolute_path);
        wchar_t *extended = (wchar_t *)xmalloc((len + 1) * sizeof(wchar_t));
        wcscpy(extended, prefix);
        wcscat(extended, absolute_path);
        return extended;
    }
}

static wchar_t *to_api_path(const wchar_t *path) {
    wchar_t *absolute_path;

    if (has_prefix(path, L"\\\\?\\") || has_prefix(path, L"\\\\.\\")) {
        return xwcsdup(path);
    }

    if (is_drive_absolute(path) || is_unc_path(path)) {
        absolute_path = xwcsdup(path);
    } else {
        DWORD needed = GetFullPathNameW(path, 0, NULL, NULL);
        if (needed == 0) {
            return xwcsdup(path);
        }

        absolute_path = (wchar_t *)xmalloc((size_t)needed * sizeof(wchar_t));
        DWORD written = GetFullPathNameW(path, needed, absolute_path, NULL);
        if (written == 0 || written >= needed) {
            free(absolute_path);
            return xwcsdup(path);
        }
    }

    {
        wchar_t *api_path = prefix_extended_path(absolute_path);
        free(absolute_path);
        return api_path;
    }
}

static wchar_t *to_absolute_path(const wchar_t *path) {
    wchar_t *absolute_path;

    if (has_prefix(path, L"\\\\?\\")) {
        if (has_prefix(path, L"\\\\?\\UNC\\")) {
            const wchar_t *without_prefix = path + 8;
            size_t len = wcslen(without_prefix) + 3;
            absolute_path = (wchar_t *)xmalloc((len + 1) * sizeof(wchar_t));
            wcscpy(absolute_path, L"\\\\");
            wcscat(absolute_path, without_prefix);
        } else {
            absolute_path = xwcsdup(path + 4);
        }
        normalize_slashes(absolute_path);
        return absolute_path;
    }

    if (is_drive_absolute(path) || is_unc_path(path)) {
        absolute_path = xwcsdup(path);
    } else {
        DWORD needed = GetFullPathNameW(path, 0, NULL, NULL);
        if (needed == 0) {
            absolute_path = xwcsdup(path);
        } else {
            absolute_path = (wchar_t *)xmalloc((size_t)needed * sizeof(wchar_t));
            DWORD written = GetFullPathNameW(path, needed, absolute_path, NULL);
            if (written == 0 || written >= needed) {
                free(absolute_path);
                absolute_path = xwcsdup(path);
            }
        }
    }

    normalize_slashes(absolute_path);
    return absolute_path;
}

static void trim_trailing_separators(wchar_t *path) {
    size_t len = wcslen(path);
    while (len > 3 && (path[len - 1] == L'\\' || path[len - 1] == L'/')) {
        path[--len] = L'\0';
    }
}

static int starts_with_case_insensitive(const wchar_t *value, const wchar_t *prefix) {
    while (*prefix) {
        if (towlower(*value) != towlower(*prefix)) {
            return 0;
        }
        value++;
        prefix++;
    }
    return 1;
}

static int equals_case_insensitive(const wchar_t *left, const wchar_t *right) {
    while (*left && *right) {
        if (towlower(*left) != towlower(*right)) {
            return 0;
        }
        left++;
        right++;
    }
    return *left == L'\0' && *right == L'\0';
}

static int path_is_under_or_equal(const wchar_t *path, const wchar_t *root_abs) {
    int result = 0;
    wchar_t *path_abs;
    wchar_t *root_copy;
    size_t root_len;

    if (!root_abs || !root_abs[0]) {
        return 0;
    }

    path_abs = to_absolute_path(path);
    root_copy = xwcsdup(root_abs);
    trim_trailing_separators(path_abs);
    trim_trailing_separators(root_copy);
    root_len = wcslen(root_copy);

    if (equals_case_insensitive(path_abs, root_copy)) {
        result = 1;
    } else if (starts_with_case_insensitive(path_abs, root_copy)) {
        if (root_len > 0 && root_copy[root_len - 1] == L'\\') {
            result = 1;
        } else if (path_abs[root_len] == L'\\') {
            result = 1;
        }
    }

    free(path_abs);
    free(root_copy);
    return result;
}

static int ends_with_separator(const wchar_t *path) {
    size_t len = wcslen(path);
    if (len == 0) {
        return 0;
    }
    return path[len - 1] == L'\\' || path[len - 1] == L'/';
}

static wchar_t *join_path(const wchar_t *base, const wchar_t *name) {
    size_t base_len = wcslen(base);
    size_t name_len = wcslen(name);
    int need_separator = base_len > 0 && !ends_with_separator(base);
    wchar_t *joined = (wchar_t *)xmalloc((base_len + need_separator + name_len + 1) * sizeof(wchar_t));

    wcscpy(joined, base);
    if (need_separator) {
        joined[base_len] = L'\\';
        joined[base_len + 1] = L'\0';
    }
    wcscat(joined, name);
    return joined;
}

static wchar_t *search_pattern_for(const wchar_t *directory) {
    return join_path(directory, L"*");
}

static const wchar_t *base_name_of(const wchar_t *path) {
    const wchar_t *last_backslash = wcsrchr(path, L'\\');
    const wchar_t *last_slash = wcsrchr(path, L'/');
    const wchar_t *last = last_backslash > last_slash ? last_backslash : last_slash;
    return last ? last + 1 : path;
}

static wchar_t *parent_path_of(const wchar_t *path) {
    wchar_t *copy = xwcsdup(path);
    wchar_t *last_backslash = wcsrchr(copy, L'\\');
    wchar_t *last_slash = wcsrchr(copy, L'/');
    wchar_t *last = last_backslash > last_slash ? last_backslash : last_slash;

    if (!last) {
        free(copy);
        return xwcsdup(L".");
    }

    if (last == copy) {
        last[1] = L'\0';
        return copy;
    }

    if (last == copy + 2 && copy[1] == L':') {
        last[1] = L'\0';
        return copy;
    }

    *last = L'\0';
    return copy;
}

static int path_exists(const wchar_t *path) {
    wchar_t *api_path = to_api_path(path);
    DWORD attrs = GetFileAttributesW(api_path);
    free(api_path);
    return attrs != INVALID_FILE_ATTRIBUTES;
}

static int directory_exists(const wchar_t *path) {
    wchar_t *api_path = to_api_path(path);
    DWORD attrs = GetFileAttributesW(api_path);
    free(api_path);
    return attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY);
}

static int ensure_directory_exists(const wchar_t *path, DWORD *error_code) {
    wchar_t *parent;
    wchar_t *api_path;
    int created;

    if (directory_exists(path)) {
        return 1;
    }

    parent = parent_path_of(path);
    if (!equals_case_insensitive(parent, path) && !directory_exists(parent)) {
        if (!ensure_directory_exists(parent, error_code)) {
            free(parent);
            return 0;
        }
    }
    free(parent);

    api_path = to_api_path(path);
    created = CreateDirectoryW(api_path, NULL);
    *error_code = created ? ERROR_SUCCESS : GetLastError();
    free(api_path);

    if (created || *error_code == ERROR_ALREADY_EXISTS) {
        return 1;
    }

    return 0;
}

static wchar_t *destination_for(const Options *options, const wchar_t *path) {
    wchar_t *absolute = to_absolute_path(path);
    wchar_t *rooted;
    wchar_t *destination;

    if (is_drive_absolute(absolute)) {
        wchar_t drive_name[2] = { (wchar_t)towupper(absolute[0]), L'\0' };
        const wchar_t *rest = absolute + 2;

        while (*rest == L'\\' || *rest == L'/') {
            rest++;
        }

        rooted = join_path(options->move_root_abs, drive_name);
        destination = join_path(rooted, rest);
        free(rooted);
    } else if (is_unc_path(absolute)) {
        const wchar_t *rest = absolute + 2;

        rooted = join_path(options->move_root_abs, L"UNC");
        destination = join_path(rooted, rest);
        free(rooted);
    } else {
        rooted = join_path(options->move_root_abs, L"UNKNOWN");
        destination = join_path(rooted, base_name_of(absolute));
        free(rooted);
    }

    free(absolute);
    return destination;
}

static wchar_t *path_with_index_suffix(const wchar_t *path, unsigned int index) {
    const wchar_t *name = base_name_of(path);
    const wchar_t *dot = wcsrchr(name, L'.');
    const wchar_t *extension = dot ? dot : path + wcslen(path);
    size_t prefix_len = (size_t)(extension - path);
    wchar_t index_text[32];
    size_t index_len;
    size_t extension_len = wcslen(extension);

    swprintf(index_text, sizeof(index_text) / sizeof(index_text[0]), L".%u", index);
    index_len = wcslen(index_text);

    wchar_t *candidate = (wchar_t *)xmalloc((prefix_len + index_len + extension_len + 1) * sizeof(wchar_t));

    wcsncpy(candidate, path, prefix_len);
    candidate[prefix_len] = L'\0';
    wcscat(candidate, index_text);
    wcscat(candidate, extension);
    return candidate;
}

static wchar_t *unique_destination(const wchar_t *desired, DWORD *error_code) {
    if (!path_exists(desired)) {
        return xwcsdup(desired);
    }

    for (unsigned int index = 1; index < 10000; index++) {
        wchar_t *candidate = path_with_index_suffix(desired, index);
        if (!path_exists(candidate)) {
            return candidate;
        }
        free(candidate);
    }

    *error_code = ERROR_ALREADY_EXISTS;
    return NULL;
}

static void move_outcome_free(MoveOutcome *outcome) {
    free(outcome->destination);
    free(outcome->error);
    outcome->destination = NULL;
    outcome->error = NULL;
}

static wchar_t *format_error_with_prefix(const wchar_t *prefix, DWORD error_code) {
    wchar_t *message = windows_error_message(error_code);
    size_t len = wcslen(prefix) + wcslen(message) + 3;
    wchar_t *combined = (wchar_t *)xmalloc((len + 1) * sizeof(wchar_t));
    wcscpy(combined, prefix);
    wcscat(combined, L": ");
    wcscat(combined, message);
    free(message);
    return combined;
}

static MoveOutcome move_encrypted_file(const Options *options, const wchar_t *path) {
    MoveOutcome outcome = {0};
    wchar_t *desired = NULL;
    wchar_t *destination = NULL;
    wchar_t *destination_parent = NULL;
    DWORD error_code = ERROR_SUCCESS;

    if (!options->move_root_abs) {
        return outcome;
    }

    outcome.attempted = 1;
    desired = destination_for(options, path);
    destination = unique_destination(desired, &error_code);
    free(desired);

    if (!destination) {
        outcome.error = format_error_with_prefix(L"Could not find unused move destination", error_code);
        return outcome;
    }

    destination_parent = parent_path_of(destination);
    if (!ensure_directory_exists(destination_parent, &error_code)) {
        outcome.destination = destination;
        outcome.error = format_error_with_prefix(L"Could not create move destination directory", error_code);
        free(destination_parent);
        return outcome;
    }
    free(destination_parent);

    {
        wchar_t *api_source = to_api_path(path);
        wchar_t *api_destination = to_api_path(destination);
        int moved = MoveFileExW(api_source, api_destination, MOVEFILE_WRITE_THROUGH);
        error_code = moved ? ERROR_SUCCESS : GetLastError();

        if (!moved && error_code == ERROR_NOT_SAME_DEVICE) {
            int copied = CopyFileW(api_source, api_destination, TRUE);
            error_code = copied ? ERROR_SUCCESS : GetLastError();
            if (copied) {
                int deleted = DeleteFileW(api_source);
                error_code = deleted ? ERROR_SUCCESS : GetLastError();
                if (!deleted) {
                    outcome.destination = destination;
                    outcome.error = format_error_with_prefix(L"Copied to destination, but could not delete original", error_code);
                    free(api_source);
                    free(api_destination);
                    return outcome;
                }
                moved = 1;
            }
        }

        free(api_source);
        free(api_destination);

        if (!moved) {
            outcome.destination = destination;
            outcome.error = format_error_with_prefix(L"Could not move encrypted file", error_code);
            return outcome;
        }
    }

    outcome.success = 1;
    outcome.destination = destination;
    return outcome;
}

static int is_dot_directory(const wchar_t *name) {
    return wcscmp(name, L".") == 0 || wcscmp(name, L"..") == 0;
}

static void stack_push(PathStack *stack, wchar_t *path) {
    if (stack->count == stack->capacity) {
        size_t new_capacity = stack->capacity ? stack->capacity * 2 : 64;
        wchar_t **new_items = (wchar_t **)realloc(stack->items, new_capacity * sizeof(wchar_t *));
        if (!new_items) {
            fwprintf(stderr, L"Out of memory\n");
            exit(2);
        }
        stack->items = new_items;
        stack->capacity = new_capacity;
    }
    stack->items[stack->count++] = path;
}

static wchar_t *stack_pop(PathStack *stack) {
    if (stack->count == 0) {
        return NULL;
    }
    return stack->items[--stack->count];
}

static void stack_free(PathStack *stack) {
    for (size_t i = 0; i < stack->count; i++) {
        free(stack->items[i]);
    }
    free(stack->items);
    stack->items = NULL;
    stack->count = 0;
    stack->capacity = 0;
}

static char *wide_to_utf8(const wchar_t *value) {
    int needed = WideCharToMultiByte(CP_UTF8, 0, value, -1, NULL, 0, NULL, NULL);
    if (needed <= 0) {
        char *fallback = (char *)xmalloc(2);
        strcpy(fallback, "?");
        return fallback;
    }

    char *buffer = (char *)xmalloc((size_t)needed);
    if (!WideCharToMultiByte(CP_UTF8, 0, value, -1, buffer, needed, NULL, NULL)) {
        buffer[0] = '?';
        buffer[1] = '\0';
    }
    return buffer;
}

static void fprint_wide_utf8(FILE *file, const wchar_t *value) {
    char *utf8 = wide_to_utf8(value);
    fputs(utf8, file);
    free(utf8);
}

static wchar_t *windows_error_message(DWORD code) {
    wchar_t *buffer = NULL;
    DWORD chars = FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        code,
        0,
        (LPWSTR)&buffer,
        0,
        NULL
    );

    if (chars == 0 || !buffer) {
        wchar_t fallback[64];
        swprintf(fallback, sizeof(fallback) / sizeof(fallback[0]), L"Windows error %lu", code);
        return xwcsdup(fallback);
    }

    while (chars > 0 && (buffer[chars - 1] == L'\r' || buffer[chars - 1] == L'\n' || buffer[chars - 1] == L' ')) {
        buffer[--chars] = L'\0';
    }

    wchar_t *message = xwcsdup(buffer);
    LocalFree(buffer);
    return message;
}

static const char *status_name(ScanStatus status) {
    switch (status) {
        case STATUS_CLEAR:
            return "CLEAR";
        case STATUS_ENCRYPTED:
            return "ENCRYPTED";
        case STATUS_SUSPECT:
            return "SUSPECT";
        case STATUS_ERROR:
            return "ERROR";
        default:
            return "UNKNOWN";
    }
}

static const char *reason_for_status(ScanStatus status) {
    switch (status) {
        case STATUS_ENCRYPTED:
            return "ShadowCube header magic and protection notice";
        case STATUS_SUSPECT:
            return "ShadowCube header magic without expected notice";
        case STATUS_CLEAR:
            return "No ShadowCube header marker";
        case STATUS_ERROR:
            return "Could not read or inspect file";
        default:
            return "Unknown";
    }
}

static void init_console(const Options *options) {
    CONSOLE_SCREEN_BUFFER_INFO info;

    stdout_handle = GetStdHandle(STD_OUTPUT_HANDLE);
    stdout_is_console = stdout_handle != INVALID_HANDLE_VALUE &&
                        stdout_handle != NULL &&
                        GetConsoleScreenBufferInfo(stdout_handle, &info);

    default_console_attributes = stdout_is_console ? info.wAttributes : 0;
    color_enabled = !options->no_color;
}

static void write_stdout_wide(const wchar_t *value) {
    if (stdout_is_console) {
        DWORD written = 0;
        WriteConsoleW(stdout_handle, value, (DWORD)wcslen(value), &written, NULL);
        return;
    }

    char *utf8 = wide_to_utf8(value);
    fputs(utf8, stdout);
    free(utf8);
}

static void log_colored_line(WORD color, const wchar_t *line) {
    if (stdout_is_console && color_enabled) {
        SetConsoleTextAttribute(stdout_handle, color);
    }

    write_stdout_wide(line);
    write_stdout_wide(L"\n");

    if (stdout_is_console && color_enabled) {
        SetConsoleTextAttribute(stdout_handle, default_console_attributes);
    }
    fflush(stdout);
}

static void log_info(unsigned long long scanned, unsigned long long elapsed_ms) {
    wchar_t line[128];
    swprintf(line, sizeof(line) / sizeof(line[0]), L"[INFO] %llu files scanned (%llums)", scanned, elapsed_ms);
    log_colored_line(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY, line);
}

static void log_found(const wchar_t *path) {
    const wchar_t *prefix = L"[FOUND] ENCRYPTED ";
    const wchar_t *suffix = L" detected";
    size_t len = wcslen(prefix) + wcslen(path) + wcslen(suffix) + 1;
    wchar_t *line = (wchar_t *)xmalloc((len + 1) * sizeof(wchar_t));

    wcscpy(line, prefix);
    wcscat(line, path);
    wcscat(line, suffix);
    log_colored_line(FOREGROUND_RED | FOREGROUND_INTENSITY, line);
    free(line);
}

static ScanStatus classify_header(const unsigned char *header, DWORD bytes_read, int loose) {
    size_t magic_len = strlen(MAGIC);
    size_t notice_len = strlen(NOTICE);

    if (bytes_read < magic_len || memcmp(header, MAGIC, magic_len) != 0) {
        return STATUS_CLEAR;
    }

    if (bytes_read >= notice_len) {
        for (DWORD index = 0; index + notice_len <= bytes_read; index++) {
            if (memcmp(header + index, NOTICE, notice_len) == 0) {
                return STATUS_ENCRYPTED;
            }
        }
    }

    return loose ? STATUS_ENCRYPTED : STATUS_SUSPECT;
}

static void report_begin(ReportWriter *report, const Options *options) {
    char timestamp[64] = {0};

    if (!options->report_path) {
        report->enabled = 0;
        report->file = NULL;
        return;
    }

    wchar_t *api_report_path = to_api_path(options->report_path);
    report->file = _wfopen(api_report_path, L"wb");
    free(api_report_path);
    if (!report->file) {
        fwprintf(stderr, L"Could not open report file: %ls\n", options->report_path);
        exit(1);
    }

    report->enabled = 1;
    fputs("\xEF\xBB\xBF", report->file);
    fputs("ShadowCube DRM scan report\n", report->file);

    {
        time_t now = time(NULL);
        struct tm local_time;
        int have_time = 0;

#ifdef _MSC_VER
        have_time = localtime_s(&local_time, &now) == 0;
#else
        struct tm *local_time_ptr = localtime(&now);
        if (local_time_ptr) {
            local_time = *local_time_ptr;
            have_time = 1;
        }
#endif

        if (have_time) {
            strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S %z", &local_time);
        }
    }

    fprintf(report->file, "Started: %s\n", timestamp[0] ? timestamp : "unknown");
    fprintf(report->file, "Mode: %s\n", options->loose ? "loose" : "strict");
    if (options->move_root_abs) {
        fputs("Move destination: ", report->file);
        fprint_wide_utf8(report->file, options->move_root_abs);
        fputc('\n', report->file);
    }
    fprintf(report->file, "Entries: %s\n\n", options->report_all ? "all files" : "encrypted, suspect, and errors only");
}

static void report_entry(
    ReportWriter *report,
    ScanStatus status,
    const wchar_t *path,
    unsigned long long size,
    const char *reason,
    const wchar_t *error,
    const MoveOutcome *move
) {
    if (!report->enabled) {
        return;
    }

    fprintf(report->file, "[%s] ", status_name(status));
    fprint_wide_utf8(report->file, path);
    if (status != STATUS_ERROR) {
        fprintf(report->file, " (%llu bytes)", size);
    }
    fprintf(report->file, "\n  reason: %s\n", reason);
    if (error && error[0]) {
        fputs("  error: ", report->file);
        fprint_wide_utf8(report->file, error);
        fputc('\n', report->file);
    }
    if (move && move->attempted) {
        fprintf(report->file, "  move: %s\n", move->success ? "success" : "failed");
        if (move->destination && move->destination[0]) {
            fputs("  destination: ", report->file);
            fprint_wide_utf8(report->file, move->destination);
            fputc('\n', report->file);
        }
        if (move->error && move->error[0]) {
            fputs("  move_error: ", report->file);
            fprint_wide_utf8(report->file, move->error);
            fputc('\n', report->file);
        }
    }
    fputc('\n', report->file);
}

static void report_end(ReportWriter *report, const Counters *counters, unsigned long long elapsed_ms) {
    if (!report->enabled) {
        return;
    }

    fputs("Summary\n", report->file);
    fprintf(report->file, "Elapsed milliseconds: %llu\n", elapsed_ms);
    fprintf(report->file, "Scanned files: %llu\n", counters->scanned);
    fprintf(report->file, "Encrypted: %llu\n", counters->encrypted);
    fprintf(report->file, "Suspect: %llu\n", counters->suspect);
    fprintf(report->file, "Clear: %llu\n", counters->clear);
    fprintf(report->file, "Errors: %llu\n", counters->errors);
    fprintf(report->file, "Move successes: %llu\n", counters->move_success);
    fprintf(report->file, "Move failures: %llu\n", counters->move_failed);
    fclose(report->file);
    report->file = NULL;
    report->enabled = 0;
}

static int should_report(const Options *options, ScanStatus status) {
    return options->report_all || status != STATUS_CLEAR;
}

static void count_status(Counters *counters, ScanStatus status) {
    switch (status) {
        case STATUS_ENCRYPTED:
            counters->encrypted++;
            break;
        case STATUS_SUSPECT:
            counters->suspect++;
            break;
        case STATUS_CLEAR:
            counters->clear++;
            break;
        case STATUS_ERROR:
            counters->errors++;
            break;
    }
}

static void record_error(
    const Options *options,
    ReportWriter *report,
    Counters *counters,
    const wchar_t *path,
    const char *reason,
    DWORD error_code
) {
    wchar_t *message = windows_error_message(error_code);
    counters->errors++;
    if (should_report(options, STATUS_ERROR)) {
        report_entry(report, STATUS_ERROR, path, 0, reason, message, NULL);
    }
    free(message);
}

static void scan_file(
    const Options *options,
    ReportWriter *report,
    Counters *counters,
    const wchar_t *path
) {
    unsigned char header[HEADER_READ_BYTES];
    DWORD bytes_read = 0;
    LARGE_INTEGER file_size;
    ScanStatus status;
    MoveOutcome move = {0};

    counters->scanned++;

    wchar_t *api_path = to_api_path(path);
    HANDLE file = CreateFileW(
        api_path,
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
        NULL
    );
    DWORD open_error = file == INVALID_HANDLE_VALUE ? GetLastError() : ERROR_SUCCESS;
    free(api_path);

    if (file == INVALID_HANDLE_VALUE) {
        record_error(options, report, counters, path, "Could not open file", open_error);
        goto progress;
    }

    file_size.QuadPart = 0;
    if (!GetFileSizeEx(file, &file_size)) {
        DWORD error_code = GetLastError();
        CloseHandle(file);
        record_error(options, report, counters, path, "Could not read file size", error_code);
        goto progress;
    }

    if (!ReadFile(file, header, HEADER_READ_BYTES, &bytes_read, NULL)) {
        DWORD error_code = GetLastError();
        CloseHandle(file);
        record_error(options, report, counters, path, "Could not read file header", error_code);
        goto progress;
    }

    CloseHandle(file);

    status = classify_header(header, bytes_read, options->loose);
    count_status(counters, status);

    if (status == STATUS_ENCRYPTED) {
        log_found(path);
        move = move_encrypted_file(options, path);
        if (move.attempted) {
            if (move.success) {
                counters->move_success++;
            } else {
                counters->move_failed++;
                counters->errors++;
            }
        }
    }

    if (should_report(options, status)) {
        unsigned long long size = file_size.QuadPart < 0 ? 0 : (unsigned long long)file_size.QuadPart;
        report_entry(report, status, path, size, reason_for_status(status), NULL, &move);
    }
    move_outcome_free(&move);

progress:
    if (options->log_every > 0 && counters->scanned % options->log_every == 0) {
        unsigned long long elapsed_ms = (unsigned long long)(GetTickCount64() - options->started_ms);
        log_info(counters->scanned, elapsed_ms);
    }
}

static void walk_directory(
    const Options *options,
    ReportWriter *report,
    Counters *counters,
    const wchar_t *root
) {
    PathStack stack = {0};
    wchar_t *directory;

    stack_push(&stack, xwcsdup(root));

    while ((directory = stack_pop(&stack)) != NULL) {
        if (options->move_root_abs && path_is_under_or_equal(directory, options->move_root_abs)) {
            free(directory);
            continue;
        }

        wchar_t *pattern = search_pattern_for(directory);
        wchar_t *api_pattern = to_api_path(pattern);
        WIN32_FIND_DATAW data;
        HANDLE find = FindFirstFileW(api_pattern, &data);
        DWORD find_error = find == INVALID_HANDLE_VALUE ? GetLastError() : ERROR_SUCCESS;
        free(pattern);
        free(api_pattern);

        if (find == INVALID_HANDLE_VALUE) {
            record_error(options, report, counters, directory, "Could not enter directory", find_error);
            free(directory);
            continue;
        }

        do {
            DWORD attrs;
            wchar_t *child;

            if (is_dot_directory(data.cFileName)) {
                continue;
            }

            attrs = data.dwFileAttributes;
            child = join_path(directory, data.cFileName);

            if (attrs & FILE_ATTRIBUTE_DIRECTORY) {
                if (options->follow_links || !(attrs & FILE_ATTRIBUTE_REPARSE_POINT)) {
                    if (options->move_root_abs && path_is_under_or_equal(child, options->move_root_abs)) {
                        free(child);
                    } else {
                        stack_push(&stack, child);
                    }
                } else {
                    free(child);
                }
            } else {
                scan_file(options, report, counters, child);
                free(child);
            }
        } while (FindNextFileW(find, &data));

        if (GetLastError() != ERROR_NO_MORE_FILES) {
            record_error(options, report, counters, directory, "Could not continue directory scan", GetLastError());
        }

        FindClose(find);
        free(directory);
    }

    stack_free(&stack);
}

static int parse_unsigned_long_long(const wchar_t *value, unsigned long long *out) {
    wchar_t *end = NULL;
    errno = 0;
    unsigned long long parsed = wcstoull(value, &end, 10);
    if (errno != 0 || !end || *end != L'\0') {
        return 0;
    }
    *out = parsed;
    return 1;
}

static void print_usage(void) {
    fputws(
        L"Usage: reverse_scanner.exe [options] <file-or-directory>...\n"
        L"\n"
        L"Options:\n"
        L"  --report <path>       Write a TXT report.\n"
        L"  --move <path>         Move encrypted files into this directory after detection.\n"
        L"  --report-all          Include clear files in the TXT report.\n"
        L"  --log-every <count>   Print [INFO] progress every N files. Default: 10000. Use 0 to disable.\n"
        L"  --loose               Treat DS3200807 alone as encrypted if the notice text changed.\n"
        L"  --follow-links        Follow directory symlinks and junctions. Disabled by default.\n"
        L"  --fail-if-found       Exit with code 2 if encrypted or suspect files are found.\n"
        L"  --no-color            Disable colored console output.\n"
        L"  --help                Show this help.\n",
        stderr
    );
}

static int parse_args(int argc, wchar_t **argv, Options *options) {
    options->loose = 0;
    options->follow_links = 0;
    options->fail_if_found = 0;
    options->no_color = 0;
    options->report_all = 0;
    options->log_every = DEFAULT_LOG_EVERY;
    options->started_ms = 0;
    options->report_path = NULL;
    options->move_path = NULL;
    options->move_root_abs = NULL;
    options->paths = (const wchar_t **)xmalloc((size_t)argc * sizeof(wchar_t *));
    options->path_count = 0;

    for (int index = 1; index < argc; index++) {
        const wchar_t *arg = argv[index];

        if (wcscmp(arg, L"--help") == 0 || wcscmp(arg, L"-h") == 0) {
            print_usage();
            return 0;
        } else if (wcscmp(arg, L"--loose") == 0) {
            options->loose = 1;
        } else if (wcscmp(arg, L"--follow-links") == 0) {
            options->follow_links = 1;
        } else if (wcscmp(arg, L"--fail-if-found") == 0) {
            options->fail_if_found = 1;
        } else if (wcscmp(arg, L"--no-color") == 0) {
            options->no_color = 1;
        } else if (wcscmp(arg, L"--report-all") == 0) {
            options->report_all = 1;
        } else if (wcscmp(arg, L"--report") == 0) {
            if (++index >= argc) {
                fwprintf(stderr, L"--report requires a path\n");
                return -1;
            }
            options->report_path = argv[index];
        } else if (wcscmp(arg, L"--move") == 0) {
            if (++index >= argc) {
                fwprintf(stderr, L"--move requires a destination directory\n");
                return -1;
            }
            options->move_path = argv[index];
        } else if (wcscmp(arg, L"--log-every") == 0) {
            if (++index >= argc) {
                fwprintf(stderr, L"--log-every requires a count\n");
                return -1;
            }
            if (!parse_unsigned_long_long(argv[index], &options->log_every)) {
                fwprintf(stderr, L"--log-every must be a non-negative integer\n");
                return -1;
            }
        } else if (arg[0] == L'-' && arg[1] == L'-') {
            fwprintf(stderr, L"Unknown option: %ls\n", arg);
            return -1;
        } else {
            options->paths[options->path_count++] = arg;
        }
    }

    if (options->move_path) {
        options->move_root_abs = to_absolute_path(options->move_path);
        trim_trailing_separators(options->move_root_abs);
    }

    if (options->path_count == 0) {
        print_usage();
        return -1;
    }

    return 1;
}

int wmain(int argc, wchar_t **argv) {
    Options options;
    Counters counters = {0};
    ReportWriter report = {0};
    int parse_result = parse_args(argc, argv, &options);
    ULONGLONG started_ms;
    unsigned long long elapsed_ms;

    if (parse_result <= 0) {
        free(options.move_root_abs);
        free((void *)options.paths);
        return parse_result == 0 ? 0 : 1;
    }

    init_console(&options);
    report_begin(&report, &options);
    started_ms = GetTickCount64();
    options.started_ms = started_ms;

    for (int index = 0; index < options.path_count; index++) {
        const wchar_t *path = options.paths[index];
        wchar_t *api_path = to_api_path(path);
        DWORD attrs = GetFileAttributesW(api_path);
        DWORD attr_error = attrs == INVALID_FILE_ATTRIBUTES ? GetLastError() : ERROR_SUCCESS;
        free(api_path);

        if (attrs == INVALID_FILE_ATTRIBUTES) {
            record_error(&options, &report, &counters, path, "Path does not exist or cannot be inspected", attr_error);
            continue;
        }

        if (options.move_root_abs && path_is_under_or_equal(path, options.move_root_abs)) {
            continue;
        }

        if (attrs & FILE_ATTRIBUTE_DIRECTORY) {
            if (!options.follow_links && (attrs & FILE_ATTRIBUTE_REPARSE_POINT)) {
                continue;
            }
            walk_directory(&options, &report, &counters, path);
        } else {
            scan_file(&options, &report, &counters, path);
        }
    }

    elapsed_ms = (unsigned long long)(GetTickCount64() - started_ms);
    report_end(&report, &counters, elapsed_ms);

    wprintf(
        L"\nScanned %llu file(s): %llu encrypted, %llu suspect, %llu clear, %llu error(s).\nElapsed: %llu ms.\n",
        counters.scanned,
        counters.encrypted,
        counters.suspect,
        counters.clear,
        counters.errors,
        elapsed_ms
    );

    if (options.move_root_abs) {
        wprintf(
            L"Move results: %llu succeeded, %llu failed.\n",
            counters.move_success,
            counters.move_failed
        );
    }

    free(options.move_root_abs);
    free((void *)options.paths);

    if (options.fail_if_found && (counters.encrypted > 0 || counters.suspect > 0)) {
        return 2;
    }

    if (counters.errors > 0) {
        return 1;
    }

    return 0;
}
