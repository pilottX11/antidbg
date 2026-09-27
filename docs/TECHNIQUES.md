# Detection techniques

`antidbg` runs several independent checks and OR-combines their results into a
flag mask. Each technique is cheap, and no single one is authoritative — the
value is in the layering, since defeating one check leaves the others standing.

| Flag                     | Platform | What it looks at | How it's fooled |
|--------------------------|----------|------------------|-----------------|
| `api_present`            | Windows  | `IsDebuggerPresent()` | Patch the PEB flag it reads |
| `api_remote`             | Windows  | `CheckRemoteDebuggerPresent()` | Hook the API |
| `peb_flag`              | Windows  | `PEB.BeingDebugged` byte, read directly | Zero the byte |
| `peb_ntglobalflag`      | Windows  | Heap debug bits in `PEB.NtGlobalFlag` | Clear the bits at startup |
| `debug_port`            | Windows  | `NtQueryInformationProcess(ProcessDebugPort)` | Hook `NtQueryInformationProcess` |
| `debug_flags`           | Windows  | `NtQueryInformationProcess(ProcessDebugFlags)` | Hook the syscall |
| `debug_object`          | Windows  | `NtQueryInformationProcess(ProcessDebugObjectHandle)` | Hook the syscall |
| `hardware_breakpoint`   | Windows  | Debug registers `Dr0`–`Dr3` via `GetThreadContext` | Clear the registers |
| `timing`                | all      | Wall-clock cost of a tight syscall loop | Patch the timer source |
| `tracer`                | Linux/macOS | `TracerPid` (Linux) / `P_TRACED` (macOS) | Hide the tracer from the kernel |
| `parent`                | Linux    | Parent process name (`gdb`, `lldb`, `strace`, …) | Launch the debugger under a different name |
| `analysis_tool`         | all      | RE tools **running on the host** (process names + window titles) | Rename the tool's binary / window |

### `analysis_tool` in detail

This one detects known reverse-engineering tools running *anywhere on the
machine*, not just those attached to your process — because an analyst usually
has IDA / Ghidra / x64dbg open before they attach anything.

- **Windows** — enumerates process executable names (`CreateToolhelp32Snapshot`)
  **and** top-level window titles (`EnumWindows`). The window-title pass is what
  catches Java-hosted tools like **Ghidra**, whose process is just `javaw.exe`
  but whose window reads "Ghidra" / "CodeBrowser".
- **Linux** — reads `/proc/<pid>/comm` and `/proc/<pid>/cmdline` (the cmdline
  pass catches Ghidra launched via `java … ghidra`).
- **macOS** — enumerates processes via `sysctl(KERN_PROC_ALL)`.

Tools detected include: **IDA** (`ida`, `ida64`, `idaq`, `idaw`, `idag`, `idat`
variants), **x64dbg / x32dbg / x96dbg**, **Ghidra**, **Binary Ninja**,
**Cutter**, **radare2 / rizin**, **OllyDbg**, **WinDbg**, **Immunity Debugger**,
**dnSpy**, **Hopper**, **Cheat Engine**, **Scylla**, **HIEW**, **JEB**,
**Process Hacker / System Informer**, **Process Monitor / Explorer**,
**Wireshark**, **Fiddler**, **PE-bear / PEStudio**, and more (see the lists in
[`src/antidbg_tools.c`](../src/antidbg_tools.c)).

> **False positives:** this is a host-wide check, so it fires on a developer's
> own machine if they happen to have any of these open. It has its own flag, so
> exclude it from the guard via `cfg.techniques` (a mask **without**
> `ADBG_ANALYSIS_TOOL`) when that trade-off is wrong for you.

## Design notes

- **Layering over cleverness.** Any one check can be neutralized by a
  determined reverse engineer. Running many raises the cost: a bypass has to
  handle every technique, and the background guard re-checks on an interval so a
  debugger attaching *after* startup still trips it.

- **No false-positive theater.** The timing threshold (25 ms for 1000 trivial
  syscalls) is deliberately generous so a busy or virtualized machine does not
  self-report as debugged. Tune `check_timing` if your workload needs a tighter
  or looser bound.

- **`ptrace(PTRACE_TRACEME)` is opt-in.** It consumes the single tracer slot as
  a side effect, so `adbg_scan()` does not run it; `TracerPid` covers the same
  ground without side effects and is repeatable.

- **This is deterrence, not DRM.** Anti-debugging raises the effort to reverse
  or tamper with your software. It does not make that impossible. Treat it as
  one layer in a defense-in-depth strategy, never as the only lock on the door.

## Extending

Add a technique by writing a `static adbg_flags check_xxx(void)` in the relevant
backend, defining a new `ADBG_*` flag in
[`include/antidbg/antidbg.h`](../include/antidbg/antidbg.h), registering its name
in `k_flag_names` in [`src/antidbg.c`](../src/antidbg.c), and calling it from that
backend's `adbg_platform_scan`.
