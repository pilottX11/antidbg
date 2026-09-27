/*
 * antidbg - Linux detection backend.
 *
 * Techniques:
 *   - /proc/self/status TracerPid != 0   (a tracer is attached right now)
 *   - ptrace(PTRACE_TRACEME) fails        (already traced; only when enabled)
 *   - parent process is a known debugger  (gdb, lldb, strace, ltrace)
 *   - execution timing anomaly
 *
 * Note: ptrace(PTRACE_TRACEME) consumes the one allowed tracer slot, so it is
 * only run when ADBG_TRACER is explicitly requested via the guard's
 * `techniques` mask. adbg_scan() (all techniques) skips it to stay
 * side-effect free and repeatable; TracerPid covers the same ground.
 */
#if defined(__linux__)

#include "antidbg_internal.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>

static adbg_flags check_tracer_pid(void)
{
    FILE *f = fopen("/proc/self/status", "r");
    char line[256];
    adbg_flags result = ADBG_NONE;

    if (!f)
        return ADBG_NONE;

    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "TracerPid:", 10) == 0) {
            long pid = strtol(line + 10, NULL, 10);
            if (pid != 0)
                result = ADBG_TRACER;
            break;
        }
    }
    fclose(f);
    return result;
}

static adbg_flags check_parent_process(void)
{
    char path[64];
    char comm[256];
    FILE *f;
    adbg_flags result = ADBG_NONE;
    static const char *suspects[] = { "gdb", "lldb", "strace", "ltrace",
                                      "valgrind", "edb", "radare2", "r2" };
    size_t i;

    pid_t ppid = getppid();
    snprintf(path, sizeof(path), "/proc/%ld/comm", (long)ppid);

    f = fopen(path, "r");
    if (!f)
        return ADBG_NONE;
    if (fgets(comm, sizeof(comm), f)) {
        size_t n = strlen(comm);
        if (n && comm[n - 1] == '\n')
            comm[n - 1] = '\0';
        for (i = 0; i < sizeof(suspects) / sizeof(suspects[0]); ++i) {
            if (strcmp(comm, suspects[i]) == 0) {
                result = ADBG_PARENT;
                break;
            }
        }
    }
    fclose(f);
    return result;
}

static adbg_flags check_timing(void)
{
    struct timespec start, end;
    double elapsed_ms;
    int i;

    if (clock_gettime(CLOCK_MONOTONIC, &start) != 0)
        return ADBG_NONE;

    for (i = 0; i < 1000; ++i) {
        volatile pid_t p = getpid();
        (void)p;
    }

    if (clock_gettime(CLOCK_MONOTONIC, &end) != 0)
        return ADBG_NONE;

    elapsed_ms = (double)(end.tv_sec - start.tv_sec) * 1000.0
               + (double)(end.tv_nsec - start.tv_nsec) / 1000000.0;

    if (elapsed_ms > 25.0)
        return ADBG_TIMING;
    return ADBG_NONE;
}

adbg_flags adbg_platform_scan(void)
{
    adbg_flags flags = ADBG_NONE;
    flags |= check_tracer_pid();
    flags |= check_parent_process();
    flags |= check_timing();
    return flags;
}

#endif /* __linux__ */

/* Avoid an empty translation unit on other platforms (ISO C forbids it). */
typedef int antidbg_antidbg_linux_tu;
