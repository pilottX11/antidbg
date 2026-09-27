/*
 * antidbg - a small, cross-platform anti-debugging library for software protection.
 *
 * Detects whether the current process is running under a debugger using a
 * layered set of independent techniques, and optionally runs a background
 * guard that reacts the moment a debugger attaches.
 *
 * Platforms: Windows, Linux, macOS.
 * License:   MIT (see LICENSE).
 *
 * Quick start:
 *
 *     #include <antidbg/antidbg.h>
 *
 *     if (adbg_detected()) {
 *         // A debugger is attached - react however you like.
 *         return 1;
 *     }
 *
 * Continuous protection:
 *
 *     void on_debugger(adbg_flags flags, void *user) {
 *         // called from a background thread when a debugger is spotted
 *         exit(1);
 *     }
 *     adbg_guard_config cfg = adbg_guard_default();
 *     cfg.on_detected = on_debugger;
 *     adbg_guard_start(&cfg);
 */
#ifndef ANTIDBG_H
#define ANTIDBG_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---- versioning ------------------------------------------------------- */

#define ANTIDBG_VERSION_MAJOR 1
#define ANTIDBG_VERSION_MINOR 0
#define ANTIDBG_VERSION_PATCH 0
#define ANTIDBG_VERSION_STRING "1.0.0"

/* ---- detection flags -------------------------------------------------- */

/*
 * Each successful detection technique sets a bit in the returned mask.
 * Techniques that do not apply to the current platform are never set.
 */
typedef uint32_t adbg_flags;

#define ADBG_NONE                 0u
#define ADBG_API_PRESENT          (1u << 0)  /* IsDebuggerPresent / TracerPid */
#define ADBG_API_REMOTE           (1u << 1)  /* CheckRemoteDebuggerPresent    */
#define ADBG_PEB_FLAG             (1u << 2)  /* PEB.BeingDebugged             */
#define ADBG_PEB_NTGLOBALFLAG     (1u << 3)  /* PEB.NtGlobalFlag heap bits    */
#define ADBG_DEBUG_PORT           (1u << 4)  /* NtQIP ProcessDebugPort        */
#define ADBG_DEBUG_FLAGS          (1u << 5)  /* NtQIP ProcessDebugFlags       */
#define ADBG_DEBUG_OBJECT         (1u << 6)  /* NtQIP ProcessDebugObjectHandle*/
#define ADBG_HARDWARE_BREAKPOINT  (1u << 7)  /* debug registers Dr0-Dr3       */
#define ADBG_TIMING               (1u << 8)  /* execution timing anomaly      */
#define ADBG_PARENT               (1u << 9)  /* suspicious parent process     */
#define ADBG_TRACER               (1u << 10) /* ptrace/TracerPid (Unix)       */
#define ADBG_ANALYSIS_TOOL        (1u << 11) /* known RE tool running on host */

/* ---- one-shot detection ---------------------------------------------- */

/*
 * Run every available detection technique once and return the combined
 * flag mask. ADBG_NONE (0) means nothing was detected.
 */
adbg_flags adbg_scan(void);

/*
 * Convenience wrapper: returns 1 if adbg_scan() found anything, else 0.
 */
int adbg_detected(void);

/*
 * Human-readable, comma-separated names for the set bits in `flags`.
 * Writes at most `size` bytes (always NUL-terminated when size > 0).
 * Returns the number of bytes that would be needed (excluding the NUL),
 * so a value >= size means the output was truncated.
 */
size_t adbg_flags_to_string(adbg_flags flags, char *buf, size_t size);

/* ---- continuous guard ------------------------------------------------- */

/*
 * Callback invoked from the guard thread when a debugger is detected.
 * `flags` is the detection mask; `user` is the pointer you supplied.
 */
typedef void (*adbg_callback)(adbg_flags flags, void *user);

typedef struct {
    unsigned      interval_ms;   /* time between scans (default 750)        */
    adbg_flags    techniques;    /* which techniques to run (0 = all)       */
    adbg_callback on_detected;   /* called on first detection (required)    */
    void         *user;          /* opaque pointer passed to the callback   */
    int           oneshot;       /* 1 = stop guard after first detection    */
} adbg_guard_config;

/*
 * A sensible default configuration: 750 ms interval, all techniques,
 * not one-shot. You still must set `on_detected`.
 */
adbg_guard_config adbg_guard_default(void);

/*
 * Start the background guard thread. Returns 0 on success, non-zero on
 * error (e.g. missing callback, thread creation failure, already running).
 * A copy of `cfg` is taken; the pointer need not outlive the call.
 */
int adbg_guard_start(const adbg_guard_config *cfg);

/*
 * Stop the guard thread and wait for it to exit. Safe to call when not
 * running. Idempotent.
 */
void adbg_guard_stop(void);

/*
 * Returns 1 if the guard thread is currently running, else 0.
 */
int adbg_guard_running(void);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* ANTIDBG_H */
