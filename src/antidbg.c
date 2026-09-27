/*
 * antidbg - platform-independent core:
 *   - adbg_scan / adbg_detected
 *   - flag-to-string formatting
 *   - the background guard thread and its lifecycle
 */
#include "antidbg_internal.h"

#include <string.h>
#include <stdio.h>

/* ---- one-shot detection ---------------------------------------------- */

/* Every source of detection combined: platform debugger checks + tool scan. */
static adbg_flags scan_all(void)
{
    return adbg_platform_scan() | adbg_scan_tools();
}

adbg_flags adbg_scan(void)
{
    return scan_all();
}

int adbg_detected(void)
{
    return adbg_scan() != ADBG_NONE;
}

/* ---- flag formatting -------------------------------------------------- */

struct adbg_flag_name {
    adbg_flags  bit;
    const char *name;
};

static const struct adbg_flag_name k_flag_names[] = {
    { ADBG_API_PRESENT,        "api_present"        },
    { ADBG_API_REMOTE,         "api_remote"         },
    { ADBG_PEB_FLAG,           "peb_flag"           },
    { ADBG_PEB_NTGLOBALFLAG,   "peb_ntglobalflag"   },
    { ADBG_DEBUG_PORT,         "debug_port"         },
    { ADBG_DEBUG_FLAGS,        "debug_flags"        },
    { ADBG_DEBUG_OBJECT,       "debug_object"       },
    { ADBG_HARDWARE_BREAKPOINT,"hardware_breakpoint"},
    { ADBG_TIMING,             "timing"             },
    { ADBG_PARENT,             "parent"             },
    { ADBG_TRACER,             "tracer"             },
    { ADBG_ANALYSIS_TOOL,      "analysis_tool"      },
};

size_t adbg_flags_to_string(adbg_flags flags, char *buf, size_t size)
{
    size_t need = 0;
    size_t i;
    int first = 1;

    if (buf && size > 0)
        buf[0] = '\0';

    if (flags == ADBG_NONE) {
        const char *none = "none";
        need = strlen(none);
        if (buf && size > 0) {
            size_t n = (need < size - 1) ? need : size - 1;
            memcpy(buf, none, n);
            buf[n] = '\0';
        }
        return need;
    }

    for (i = 0; i < sizeof(k_flag_names) / sizeof(k_flag_names[0]); ++i) {
        const char *name;
        size_t name_len;

        if (!(flags & k_flag_names[i].bit))
            continue;

        name = k_flag_names[i].name;
        name_len = strlen(name);

        if (!first) {
            if (buf && need + 1 < size) buf[need] = ',';
            need += 1;
        }
        first = 0;

        if (buf && need < size) {
            size_t space = size - 1 - need;
            size_t n = (name_len < space) ? name_len : space;
            memcpy(buf + need, name, n);
            buf[need + n] = '\0';
        }
        need += name_len;
    }

    return need;
}

/* ---- guard thread ----------------------------------------------------- */

adbg_guard_config adbg_guard_default(void)
{
    adbg_guard_config cfg;
    cfg.interval_ms = 750;
    cfg.techniques  = 0;     /* 0 == run everything */
    cfg.on_detected = NULL;
    cfg.user        = NULL;
    cfg.oneshot     = 0;
    return cfg;
}

/*
 * Threading and sleeping differ per platform. We keep the guard logic here
 * and isolate the few primitives we need behind a tiny shim.
 */
#if defined(_WIN32)

#include <windows.h>

typedef HANDLE            adbg_thread_t;
typedef CRITICAL_SECTION  adbg_mutex_t;

static void adbg_sleep_ms(unsigned ms)         { Sleep(ms); }
static void adbg_mutex_init(adbg_mutex_t *m)   { InitializeCriticalSection(m); }
static void adbg_mutex_free(adbg_mutex_t *m)   { DeleteCriticalSection(m); }
static void adbg_mutex_lock(adbg_mutex_t *m)   { EnterCriticalSection(m); }
static void adbg_mutex_unlock(adbg_mutex_t *m) { LeaveCriticalSection(m); }

#else

#include <pthread.h>
#include <time.h>

typedef pthread_t        adbg_thread_t;
typedef pthread_mutex_t  adbg_mutex_t;

static void adbg_sleep_ms(unsigned ms)
{
    struct timespec ts;
    ts.tv_sec  = (time_t)(ms / 1000u);
    ts.tv_nsec = (long)(ms % 1000u) * 1000000L;
    nanosleep(&ts, NULL);
}
static void adbg_mutex_init(adbg_mutex_t *m)   { pthread_mutex_init(m, NULL); }
static void adbg_mutex_free(adbg_mutex_t *m)   { pthread_mutex_destroy(m); }
static void adbg_mutex_lock(adbg_mutex_t *m)   { pthread_mutex_lock(m); }
static void adbg_mutex_unlock(adbg_mutex_t *m) { pthread_mutex_unlock(m); }

#endif

static struct {
    adbg_guard_config cfg;
    adbg_thread_t     thread;
    adbg_mutex_t      lock;
    volatile int      running;
    volatile int      stop;
    int               initialized;
} g_guard;

static int guard_should_stop(void)
{
    int s;
    adbg_mutex_lock(&g_guard.lock);
    s = g_guard.stop;
    adbg_mutex_unlock(&g_guard.lock);
    return s;
}

static void guard_loop(void)
{
    for (;;) {
        adbg_flags found;

        if (guard_should_stop())
            break;

        found = scan_all();
        if (g_guard.cfg.techniques != 0)
            found &= g_guard.cfg.techniques;

        if (found != ADBG_NONE) {
            if (g_guard.cfg.on_detected)
                g_guard.cfg.on_detected(found, g_guard.cfg.user);
            if (g_guard.cfg.oneshot)
                break;
        }

        /* Sleep in small slices so stop() stays responsive. */
        {
            unsigned remaining = g_guard.cfg.interval_ms;
            while (remaining > 0 && !guard_should_stop()) {
                unsigned slice = remaining < 50u ? remaining : 50u;
                adbg_sleep_ms(slice);
                remaining -= slice;
            }
        }
    }

    adbg_mutex_lock(&g_guard.lock);
    g_guard.running = 0;
    adbg_mutex_unlock(&g_guard.lock);
}

#if defined(_WIN32)
static DWORD WINAPI guard_thread_entry(LPVOID arg)
{
    (void)arg;
    guard_loop();
    return 0;
}
#else
static void *guard_thread_entry(void *arg)
{
    (void)arg;
    guard_loop();
    return NULL;
}
#endif

int adbg_guard_running(void)
{
    int r;
    if (!g_guard.initialized)
        return 0;
    adbg_mutex_lock(&g_guard.lock);
    r = g_guard.running;
    adbg_mutex_unlock(&g_guard.lock);
    return r;
}

int adbg_guard_start(const adbg_guard_config *cfg)
{
    if (!cfg || !cfg->on_detected)
        return 1;

    if (!g_guard.initialized) {
        adbg_mutex_init(&g_guard.lock);
        g_guard.initialized = 1;
    }

    if (adbg_guard_running())
        return 2;

    adbg_mutex_lock(&g_guard.lock);
    g_guard.cfg  = *cfg;
    if (g_guard.cfg.interval_ms == 0)
        g_guard.cfg.interval_ms = 750;
    g_guard.stop    = 0;
    g_guard.running = 1;
    adbg_mutex_unlock(&g_guard.lock);

#if defined(_WIN32)
    g_guard.thread = CreateThread(NULL, 0, guard_thread_entry, NULL, 0, NULL);
    if (g_guard.thread == NULL) {
        adbg_mutex_lock(&g_guard.lock);
        g_guard.running = 0;
        adbg_mutex_unlock(&g_guard.lock);
        return 3;
    }
#else
    if (pthread_create(&g_guard.thread, NULL, guard_thread_entry, NULL) != 0) {
        adbg_mutex_lock(&g_guard.lock);
        g_guard.running = 0;
        adbg_mutex_unlock(&g_guard.lock);
        return 3;
    }
#endif
    return 0;
}

void adbg_guard_stop(void)
{
    if (!g_guard.initialized)
        return;

    adbg_mutex_lock(&g_guard.lock);
    if (!g_guard.running && !g_guard.stop) {
        adbg_mutex_unlock(&g_guard.lock);
        return;
    }
    g_guard.stop = 1;
    adbg_mutex_unlock(&g_guard.lock);

#if defined(_WIN32)
    if (g_guard.thread) {
        WaitForSingleObject(g_guard.thread, INFINITE);
        CloseHandle(g_guard.thread);
        g_guard.thread = NULL;
    }
#else
    pthread_join(g_guard.thread, NULL);
#endif
}
