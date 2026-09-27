/*
 * antidbg - reverse-engineering tool scanner.
 *
 * Detects known analysis tools *running on the host*, even when they are not
 * attached to this process. This complements the "am I being debugged?"
 * checks: an analyst usually has IDA / Ghidra / Binary Ninja / x64dbg open
 * before they ever attach.
 *
 * Two signals are used on Windows:
 *   1. Process executable names (Toolhelp snapshot).
 *   2. Top-level window titles (EnumWindows) - this catches Java-hosted tools
 *      like Ghidra whose process is just "javaw.exe" but whose window says
 *      "Ghidra" / "CodeBrowser".
 * On Linux we read /proc/<pid>/comm and /proc/<pid>/cmdline (cmdline catches
 * Ghidra launched via `java ... ghidra`). On macOS we enumerate via sysctl.
 *
 * NOTE: this is a host-wide check and can legitimately fire on a developer's
 * own machine. It is exposed as its own flag (ADBG_ANALYSIS_TOOL) so callers
 * can exclude it via the guard's `techniques` mask if that trade-off is wrong
 * for them.
 */
#include "antidbg_internal.h"

#include <string.h>

/* ---- shared match data ------------------------------------------------ */

/*
 * Substrings matched (case-insensitively) against a process's executable
 * basename. Chosen to be specific enough to avoid common collisions (note:
 * IDA is handled via exact names below, so "AIDA64" does not false-positive).
 */
static const char *const k_proc_substr[] = {
    "x64dbg", "x32dbg", "x96dbg", "x64_dbg",
    "ollydbg", "windbg", "immunitydebugger",
    "ghidra", "binaryninja", "cutter", "dnspy",
    "hopper", "radare2", "rizin", "cheatengine",
    "scylla", "hiew", "jeb", "retdec",
    "processhacker", "systeminformer", "procmon", "procexp",
    "wireshark", "fiddler", "tcpview", "apimonitor",
    "pestudio", "petools", "dumpcap", "x64dbgpy",
};

/*
 * Exact basename matches (case-insensitive). Used for names too short to
 * match as substrings safely (ida, r2, gdb) and for the full IDA variants.
 */
static const char *const k_proc_exact[] = {
    "ida", "ida.exe", "ida64", "ida64.exe",
    "idaq", "idaq.exe", "idaq64", "idaq64.exe",
    "idaw", "idaw.exe", "idaw64", "idaw64.exe",
    "idag", "idag.exe", "idag64", "idag64.exe",
    "idat", "idat.exe", "idat64", "idat64.exe",
    "gdb", "lldb", "r2", "edb", "edb.exe",
};

/* ---- case-insensitive helpers ---------------------------------------- */

static int ci_char_eq(char a, char b)
{
    if (a >= 'A' && a <= 'Z') a = (char)(a - 'A' + 'a');
    if (b >= 'A' && b <= 'Z') b = (char)(b - 'A' + 'a');
    return a == b;
}

static int ci_equals(const char *a, const char *b)
{
    while (*a && *b) {
        if (!ci_char_eq(*a, *b))
            return 0;
        ++a; ++b;
    }
    return *a == '\0' && *b == '\0';
}

static int ci_contains(const char *hay, const char *needle)
{
    if (!hay || !needle || !*needle)
        return 0;
    for (; *hay; ++hay) {
        const char *h = hay;
        const char *n = needle;
        while (*h && *n && ci_char_eq(*h, *n)) { ++h; ++n; }
        if (*n == '\0')
            return 1;
    }
    return 0;
}

/* Match an executable basename against the substring + exact lists. */
static int proc_name_is_tool(const char *name)
{
    size_t i;
    if (!name || !*name)
        return 0;
    for (i = 0; i < sizeof(k_proc_substr) / sizeof(k_proc_substr[0]); ++i)
        if (ci_contains(name, k_proc_substr[i]))
            return 1;
    for (i = 0; i < sizeof(k_proc_exact) / sizeof(k_proc_exact[0]); ++i)
        if (ci_equals(name, k_proc_exact[i]))
            return 1;
    return 0;
}

/* Match arbitrary text (e.g. a command line) against the substring list. */
static int text_has_tool(const char *text)
{
    size_t i;
    if (!text || !*text)
        return 0;
    for (i = 0; i < sizeof(k_proc_substr) / sizeof(k_proc_substr[0]); ++i)
        if (ci_contains(text, k_proc_substr[i]))
            return 1;
    return 0;
}

/* =====================================================================
 *  Windows
 * ===================================================================== */
#if defined(_WIN32)

#include <windows.h>
#include <tlhelp32.h>

/* Window-title keywords - complements process names (catches Ghidra etc.). */
static const char *const k_window_substr[] = {
    "ghidra", "binary ninja", "ida pro", "ida - ",
    "x64dbg", "x32dbg", "x96dbg", "ollydbg",
    "immunity debugger", "cutter", "dnspy", "hopper",
    "windbg", "cheat engine",
};

static int scan_processes(void)
{
    HANDLE snap;
    PROCESSENTRY32 pe;
    int found = 0;

    snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE)
        return 0;

    pe.dwSize = sizeof(pe);
    if (Process32First(snap, &pe)) {
        do {
            if (proc_name_is_tool(pe.szExeFile)) {
                found = 1;
                break;
            }
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    return found;
}

static BOOL CALLBACK window_cb(HWND hwnd, LPARAM lparam)
{
    char title[512];
    int *found = (int *)lparam;
    size_t i;

    if (!IsWindowVisible(hwnd))
        return TRUE;
    if (GetWindowTextA(hwnd, title, (int)sizeof(title)) <= 0)
        return TRUE;

    for (i = 0; i < sizeof(k_window_substr) / sizeof(k_window_substr[0]); ++i) {
        if (ci_contains(title, k_window_substr[i])) {
            *found = 1;
            return FALSE; /* stop enumerating */
        }
    }
    return TRUE;
}

static int scan_windows(void)
{
    int found = 0;
    EnumWindows(window_cb, (LPARAM)&found);
    return found;
}

adbg_flags adbg_scan_tools(void)
{
    (void)text_has_tool; /* used on the Linux path only */
    if (scan_processes() || scan_windows())
        return ADBG_ANALYSIS_TOOL;
    return ADBG_NONE;
}

/* =====================================================================
 *  Linux
 * ===================================================================== */
#elif defined(__linux__)

#include <stdio.h>
#include <dirent.h>
#include <ctype.h>

static int read_first_line(const char *path, char *buf, size_t size)
{
    FILE *f = fopen(path, "r");
    size_t n;
    if (!f)
        return 0;
    n = fread(buf, 1, size - 1, f);
    fclose(f);
    buf[n] = '\0';
    /* comm has a trailing newline; strip it. */
    while (n && (buf[n - 1] == '\n' || buf[n - 1] == '\r'))
        buf[--n] = '\0';
    return 1;
}

static int read_cmdline(const char *path, char *buf, size_t size)
{
    /* cmdline is NUL-separated; turn NULs into spaces so we can substring it. */
    FILE *f = fopen(path, "r");
    size_t n, i;
    if (!f)
        return 0;
    n = fread(buf, 1, size - 1, f);
    fclose(f);
    for (i = 0; i < n; ++i)
        if (buf[i] == '\0')
            buf[i] = ' ';
    buf[n] = '\0';
    return 1;
}

adbg_flags adbg_scan_tools(void)
{
    DIR *proc;
    struct dirent *ent;
    int found = 0;

    proc = opendir("/proc");
    if (!proc)
        return ADBG_NONE;

    while (!found && (ent = readdir(proc)) != NULL) {
        char path[64];
        char buf[4096];
        const char *p = ent->d_name;

        /* Only numeric entries are PIDs. */
        if (!isdigit((unsigned char)p[0]))
            continue;

        snprintf(path, sizeof(path), "/proc/%s/comm", p);
        if (read_first_line(path, buf, sizeof(buf)) && proc_name_is_tool(buf)) {
            found = 1;
            break;
        }

        snprintf(path, sizeof(path), "/proc/%s/cmdline", p);
        if (read_cmdline(path, buf, sizeof(buf)) && text_has_tool(buf)) {
            found = 1;
            break;
        }
    }
    closedir(proc);

    return found ? ADBG_ANALYSIS_TOOL : ADBG_NONE;
}

/* =====================================================================
 *  macOS
 * ===================================================================== */
#elif defined(__APPLE__)

#include <sys/sysctl.h>
#include <stdlib.h>

adbg_flags adbg_scan_tools(void)
{
    int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0 };
    size_t len = 0;
    struct kinfo_proc *procs;
    size_t count, i;
    int found = 0;

    (void)text_has_tool; /* used on the Linux path only */

    if (sysctl(mib, 4, NULL, &len, NULL, 0) != 0 || len == 0)
        return ADBG_NONE;

    procs = (struct kinfo_proc *)malloc(len);
    if (!procs)
        return ADBG_NONE;

    if (sysctl(mib, 4, procs, &len, NULL, 0) != 0) {
        free(procs);
        return ADBG_NONE;
    }

    count = len / sizeof(struct kinfo_proc);
    for (i = 0; i < count; ++i) {
        /* p_comm is truncated (MAXCOMLEN), but enough for most tool names. */
        if (proc_name_is_tool(procs[i].kp_proc.p_comm)) {
            found = 1;
            break;
        }
    }
    free(procs);

    return found ? ADBG_ANALYSIS_TOOL : ADBG_NONE;
}

/* =====================================================================
 *  Other platforms
 * ===================================================================== */
#else

adbg_flags adbg_scan_tools(void)
{
    (void)proc_name_is_tool;
    (void)text_has_tool;
    return ADBG_NONE;
}

#endif
