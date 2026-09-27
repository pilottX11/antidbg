/*
 * protect.c - continuous background protection.
 *
 * Starts the guard thread, then does "work". If a debugger attaches at any
 * point, the callback fires from the guard thread and we react (here we just
 * print and exit; real software might wipe secrets, corrupt state, or bail).
 */
#include <antidbg/antidbg.h>
#include <stdio.h>
#include <stdlib.h>

#if defined(_WIN32)
#include <windows.h>
static void nap(unsigned ms) { Sleep(ms); }
#else
#include <time.h>
static void nap(unsigned ms)
{
    struct timespec ts;
    ts.tv_sec = ms / 1000u;
    ts.tv_nsec = (long)(ms % 1000u) * 1000000L;
    nanosleep(&ts, NULL);
}
#endif

static void on_debugger(adbg_flags flags, void *user)
{
    char names[256];
    (void)user;
    adbg_flags_to_string(flags, names, sizeof(names));
    fprintf(stderr, "\n[antidbg] debugger detected (%s) - aborting.\n", names);
    /* In real software: clear keys, tear down state, then exit hard. */
    _Exit(1);
}

int main(void)
{
    adbg_guard_config cfg = adbg_guard_default();
    cfg.interval_ms = 500;
    cfg.on_detected = on_debugger;

    if (adbg_guard_start(&cfg) != 0) {
        fprintf(stderr, "failed to start guard\n");
        return 2;
    }

    printf("protected work running. attach a debugger to trip the guard.\n");
    printf("(press Ctrl+C to quit)\n");

    for (;;) {
        printf("working... (guard running: %d)\n", adbg_guard_running());
        nap(1000);
    }

    adbg_guard_stop(); /* unreachable here, but this is how you stop it */
    return 0;
}
