/*
 * antidbg - macOS detection backend.
 *
 * Techniques:
 *   - sysctl(KERN_PROC) P_TRACED flag  (the canonical macOS debugger check)
 *   - execution timing anomaly
 */
#if defined(__APPLE__)

#include "antidbg_internal.h"

#include <sys/types.h>
#include <sys/sysctl.h>
#include <unistd.h>
#include <string.h>
#include <time.h>

static adbg_flags check_p_traced(void)
{
    int mib[4];
    struct kinfo_proc info;
    size_t size = sizeof(info);

    memset(&info, 0, sizeof(info));
    mib[0] = CTL_KERN;
    mib[1] = KERN_PROC;
    mib[2] = KERN_PROC_PID;
    mib[3] = getpid();

    if (sysctl(mib, 4, &info, &size, NULL, 0) != 0)
        return ADBG_NONE;

    if (info.kp_proc.p_flag & P_TRACED)
        return ADBG_TRACER;
    return ADBG_NONE;
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
    flags |= check_p_traced();
    flags |= check_timing();
    return flags;
}

#endif /* __APPLE__ */

/* Avoid an empty translation unit on other platforms (ISO C forbids it). */
typedef int antidbg_antidbg_macos_tu;
