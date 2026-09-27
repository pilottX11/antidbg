/*
 * antidbg - Windows detection backend.
 *
 * Layered techniques, from cheapest to most thorough:
 *   - IsDebuggerPresent()                (documented API)
 *   - CheckRemoteDebuggerPresent()       (documented API)
 *   - PEB.BeingDebugged                  (direct structure read)
 *   - PEB.NtGlobalFlag heap debug bits   (set by the loader under a debugger)
 *   - NtQueryInformationProcess:
 *         ProcessDebugPort               (non-zero port => user-mode debugger)
 *         ProcessDebugFlags              (zero => debugger present)
 *         ProcessDebugObjectHandle       (valid handle => debug object exists)
 *   - Hardware breakpoints in Dr0-Dr3    (GetThreadContext)
 *   - Timing anomaly around a syscall    (single-stepping/breakpoint slowdown)
 */
#if defined(_WIN32)

#include "antidbg_internal.h"

#include <windows.h>

/* ---- ntdll bits we need but don't get from the SDK headers ------------ */

typedef LONG NTSTATUS;
#ifndef NT_SUCCESS
#define NT_SUCCESS(s) ((NTSTATUS)(s) >= 0)
#endif

/* Subset of PROCESSINFOCLASS values used here. */
#define ProcessDebugPort          7
#define ProcessDebugObjectHandle  30
#define ProcessDebugFlags         31

typedef NTSTATUS (WINAPI *pfn_NtQueryInformationProcess)(
    HANDLE ProcessHandle,
    ULONG  ProcessInformationClass,
    PVOID  ProcessInformation,
    ULONG  ProcessInformationLength,
    PULONG ReturnLength);

static pfn_NtQueryInformationProcess resolve_nt_qip(void)
{
    static pfn_NtQueryInformationProcess cached = NULL;
    static int tried = 0;
    if (!tried) {
        HMODULE ntdll = GetModuleHandleA("ntdll.dll");
        if (ntdll)
            cached = (pfn_NtQueryInformationProcess)
                GetProcAddress(ntdll, "NtQueryInformationProcess");
        tried = 1;
    }
    return cached;
}

/* ---- PEB access ------------------------------------------------------- */
/*
 * We read the PEB via the documented offsets. The PEB pointer lives in the
 * TEB, reachable through the GS/FS segment register on x64/x86 respectively.
 * BeingDebugged is at PEB+0x02; NtGlobalFlag at PEB+0x68 (x86) / +0xBC (x64).
 */

#if defined(_M_X64) || defined(__x86_64__)
#include <intrin.h>
static BYTE *get_peb(void)
{
    return (BYTE *)__readgsqword(0x60);
}
#define ADBG_NTGLOBALFLAG_OFFSET 0xBC
#elif defined(_M_IX86) || defined(__i386__)
static BYTE *get_peb(void)
{
    BYTE *peb;
#if defined(_MSC_VER)
    __asm {
        mov eax, fs:[0x30]
        mov peb, eax
    }
#else
    __asm__ __volatile__("mov %%fs:0x30, %0" : "=r"(peb));
#endif
    return peb;
}
#define ADBG_NTGLOBALFLAG_OFFSET 0x68
#else
static BYTE *get_peb(void) { return NULL; }
#define ADBG_NTGLOBALFLAG_OFFSET 0
#endif

/* Heap-related flags the loader sets in NtGlobalFlag when a debugger is present. */
#define FLG_HEAP_ENABLE_TAIL_CHECK   0x10
#define FLG_HEAP_ENABLE_FREE_CHECK   0x20
#define FLG_HEAP_VALIDATE_PARAMETERS 0x40
#define NT_GLOBAL_FLAG_DEBUG_BITS \
    (FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS)

/* ---- individual checks ------------------------------------------------ */

static adbg_flags check_api_present(void)
{
    return IsDebuggerPresent() ? ADBG_API_PRESENT : ADBG_NONE;
}

static adbg_flags check_remote_present(void)
{
    BOOL present = FALSE;
    if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &present) && present)
        return ADBG_API_REMOTE;
    return ADBG_NONE;
}

static adbg_flags check_peb_being_debugged(void)
{
    BYTE *peb = get_peb();
    if (peb && peb[0x02] != 0)
        return ADBG_PEB_FLAG;
    return ADBG_NONE;
}

static adbg_flags check_peb_ntglobalflag(void)
{
    BYTE *peb = get_peb();
    if (peb && ADBG_NTGLOBALFLAG_OFFSET) {
        DWORD flag = *(DWORD *)(peb + ADBG_NTGLOBALFLAG_OFFSET);
        if (flag & NT_GLOBAL_FLAG_DEBUG_BITS)
            return ADBG_PEB_NTGLOBALFLAG;
    }
    return ADBG_NONE;
}

static adbg_flags check_debug_port(void)
{
    pfn_NtQueryInformationProcess qip = resolve_nt_qip();
    DWORD_PTR port = 0;
    NTSTATUS st;
    if (!qip)
        return ADBG_NONE;
    st = qip(GetCurrentProcess(), ProcessDebugPort,
             &port, sizeof(port), NULL);
    if (NT_SUCCESS(st) && port != 0)
        return ADBG_DEBUG_PORT;
    return ADBG_NONE;
}

static adbg_flags check_debug_flags(void)
{
    pfn_NtQueryInformationProcess qip = resolve_nt_qip();
    DWORD flags = 0;
    NTSTATUS st;
    if (!qip)
        return ADBG_NONE;
    st = qip(GetCurrentProcess(), ProcessDebugFlags,
             &flags, sizeof(flags), NULL);
    /* ProcessDebugFlags == 0 means "no debug inherit" is off => debugged. */
    if (NT_SUCCESS(st) && flags == 0)
        return ADBG_DEBUG_FLAGS;
    return ADBG_NONE;
}

static adbg_flags check_debug_object(void)
{
    pfn_NtQueryInformationProcess qip = resolve_nt_qip();
    HANDLE obj = NULL;
    NTSTATUS st;
    if (!qip)
        return ADBG_NONE;
    st = qip(GetCurrentProcess(), ProcessDebugObjectHandle,
             &obj, sizeof(obj), NULL);
    if (NT_SUCCESS(st) && obj != NULL)
        return ADBG_DEBUG_OBJECT;
    return ADBG_NONE;
}

static adbg_flags check_hardware_breakpoints(void)
{
    CONTEXT ctx;
    ZeroMemory(&ctx, sizeof(ctx));
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (GetThreadContext(GetCurrentThread(), &ctx)) {
        if (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3)
            return ADBG_HARDWARE_BREAKPOINT;
    }
    return ADBG_NONE;
}

static adbg_flags check_timing(void)
{
    /*
     * Time a short burst of trivial syscalls. Under a debugger that is
     * single-stepping or trapping, the wall-clock cost balloons well past
     * what native execution needs. The threshold is deliberately generous
     * to avoid false positives on loaded machines.
     */
    LARGE_INTEGER freq, start, end;
    double elapsed_ms;
    int i;

    if (!QueryPerformanceFrequency(&freq) || freq.QuadPart == 0)
        return ADBG_NONE;

    QueryPerformanceCounter(&start);
    for (i = 0; i < 1000; ++i) {
        /* GetProcessHeap is a cheap, side-effect-free syscall-ish call. */
        volatile HANDLE h = GetProcessHeap();
        (void)h;
    }
    QueryPerformanceCounter(&end);

    elapsed_ms = (double)(end.QuadPart - start.QuadPart) * 1000.0
               / (double)freq.QuadPart;

    if (elapsed_ms > 25.0)
        return ADBG_TIMING;
    return ADBG_NONE;
}

/* ---- backend entry point --------------------------------------------- */

adbg_flags adbg_platform_scan(void)
{
    adbg_flags flags = ADBG_NONE;
    flags |= check_api_present();
    flags |= check_remote_present();
    flags |= check_peb_being_debugged();
    flags |= check_peb_ntglobalflag();
    flags |= check_debug_port();
    flags |= check_debug_flags();
    flags |= check_debug_object();
    flags |= check_hardware_breakpoints();
    flags |= check_timing();
    return flags;
}

#endif /* _WIN32 */

/* Avoid an empty translation unit on other platforms (ISO C forbids it). */
typedef int antidbg_antidbg_windows_tu;
