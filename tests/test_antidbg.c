/*
 * test_antidbg.c - lightweight self-tests that do not require a debugger.
 *
 * These validate the pieces we can check deterministically: flag formatting,
 * guard lifecycle, and that a plain scan runs without crashing. Whether a
 * debugger is *detected* is environment-dependent, so we don't assert on it.
 */
#include <antidbg/antidbg.h>

#include <stdio.h>
#include <string.h>

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

static int failures = 0;

#define CHECK(cond, msg) do {                          \
        if (!(cond)) {                                 \
            printf("FAIL: %s\n", msg);                 \
            failures++;                                \
        } else {                                       \
            printf("ok:   %s\n", msg);                 \
        }                                              \
    } while (0)

static void test_flags_to_string(void)
{
    char buf[256];
    size_t n;

    n = adbg_flags_to_string(ADBG_NONE, buf, sizeof(buf));
    CHECK(strcmp(buf, "none") == 0, "ADBG_NONE formats as \"none\"");
    CHECK(n == 4, "ADBG_NONE length is 4");

    adbg_flags_to_string(ADBG_TIMING, buf, sizeof(buf));
    CHECK(strcmp(buf, "timing") == 0, "single flag formats by name");

    adbg_flags_to_string(ADBG_API_PRESENT | ADBG_TIMING, buf, sizeof(buf));
    CHECK(strcmp(buf, "api_present,timing") == 0, "multiple flags comma-joined");

    adbg_flags_to_string(ADBG_ANALYSIS_TOOL, buf, sizeof(buf));
    CHECK(strcmp(buf, "analysis_tool") == 0, "analysis_tool flag formats by name");

    /* Truncation must always NUL-terminate and report full needed length. */
    n = adbg_flags_to_string(ADBG_API_PRESENT | ADBG_TIMING, buf, 5);
    CHECK(buf[4] == '\0', "truncated output stays NUL-terminated");
    CHECK(n > 4, "truncation reports full required length");
}

static void test_scan_runs(void)
{
    adbg_flags f = adbg_scan();
    /* Just make sure it returns and detected() agrees with the mask. */
    CHECK((f != ADBG_NONE) == (adbg_detected() != 0),
          "adbg_detected agrees with adbg_scan");
}

static volatile int g_cb_hits = 0;
static void counting_cb(adbg_flags flags, void *user)
{
    (void)flags; (void)user;
    g_cb_hits++;
}

static void test_guard_lifecycle(void)
{
    adbg_guard_config cfg = adbg_guard_default();

    CHECK(adbg_guard_start(NULL) != 0, "start rejects NULL config");

    cfg.on_detected = NULL;
    CHECK(adbg_guard_start(&cfg) != 0, "start rejects missing callback");

    cfg.on_detected = counting_cb;
    cfg.interval_ms = 50;
    CHECK(adbg_guard_start(&cfg) == 0, "guard starts with valid config");
    CHECK(adbg_guard_running() == 1, "guard reports running");
    CHECK(adbg_guard_start(&cfg) == 2, "second start is rejected");

    nap(200);

    adbg_guard_stop();
    CHECK(adbg_guard_running() == 0, "guard reports stopped");

    adbg_guard_stop(); /* idempotent */
    CHECK(adbg_guard_running() == 0, "double stop is safe");
}

int main(void)
{
    printf("== antidbg self-tests ==\n");
    test_flags_to_string();
    test_scan_runs();
    test_guard_lifecycle();

    printf("\n%s (%d failure%s)\n",
           failures == 0 ? "ALL PASSED" : "FAILURES",
           failures, failures == 1 ? "" : "s");
    return failures == 0 ? 0 : 1;
}
