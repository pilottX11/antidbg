<div align="center">

# antidbg

**A small, cross-platform anti-debugging library for software protection.**

Detect and react to debuggers in your process — with one line of code.

[![CI](https://img.shields.io/github/actions/workflow/status/OWNER/antidbg/ci.yml?branch=main&label=build)](../../actions)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
![Language: C99](https://img.shields.io/badge/language-C++-blue.svg)
![Platforms](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-informational.svg)
![Dependencies](https://img.shields.io/badge/dependencies-none-success.svg)
![Version](https://img.shields.io/badge/version-1.0.0-orange.svg)

</div>

> Replace `OWNER` in the CI badge above with your GitHub org/user once you push.

---

`antidbg` runs a layered set of independent checks — documented APIs, direct
PEB reads, `NtQueryInformationProcess`, hardware-breakpoint registers, and
timing anomalies — and combines them into a single result. It also ships a
background **guard** that re-checks on an interval, so a debugger that attaches
*after* startup still trips it.

No dependencies. No build system lock-in. Drop it in and go.

## Features

- **One-line detection** — `if (adbg_detected()) { ... }`
- **Continuous guard** — a background thread that fires your callback the moment a debugger appears
- **Spots RE tools on the host** — IDA, Ghidra, Binary Ninja, x64dbg, Cutter, dnSpy, Process Hacker & more, even before they attach ([how](docs/TECHNIQUES.md#analysis_tool-in-detail))
- **10+ techniques** across Windows, Linux, and macOS ([details](docs/TECHNIQUES.md))
- **Zero dependencies** — just the C standard library + OS APIs
- **Tiny & portable** — C99, static or shared, ~600 lines
- **Python binding** included via `ctypes`

## Quick start

```c
#include <antidbg/antidbg.h>

int main(void) {
    if (adbg_detected()) {
        // A debugger is attached — react however you like.
        return 1;
    }
    // ... your protected code ...
}
```

Continuous protection with a background guard:

```c
#include <antidbg/antidbg.h>

static void on_debugger(adbg_flags flags, void *user) {
    // Called from the guard thread. Wipe secrets, then bail.
    _Exit(1);
}

int main(void) {
    adbg_guard_config cfg = adbg_guard_default();
    cfg.on_detected = on_debugger;
    adbg_guard_start(&cfg);   // now protected for the life of the process
    // ... your protected code ...
}
```

## Setup

### Build & test (one command)

```bash
./build.sh          # Linux / macOS
```

```bat
build.bat           REM Windows (needs CMake + a C toolchain)
```

### Or with CMake directly

```bash
cmake -B build
cmake --build build
ctest --test-dir build --output-on-failure
```

### Use it in your CMake project

```cmake
add_subdirectory(antidbg)
target_link_libraries(your_app PRIVATE antidbg::antidbg)
```

### Or just drop in the sources

```bash
cc -Iantidbg/include your_app.c \
   antidbg/src/antidbg.c antidbg/src/antidbg_*.c -o your_app
```

### Python

```bash
cmake -B build -DANTIDBG_SHARED=ON && cmake --build build
python bindings/python/antidbg.py     # prints "clean" or "detected"
```

```python
import antidbg
if antidbg.detected():
    print("running under a debugger:", antidbg.flags_to_string(antidbg.scan()))
```

## API

| Function | Description |
|----------|-------------|
| `adbg_flags adbg_scan(void)` | Run every check once; returns a bit mask of what fired. |
| `int adbg_detected(void)` | `1` if anything was detected, else `0`. |
| `adbg_flags_to_string(flags, buf, size)` | Human-readable names for set flags. |
| `adbg_guard_default()` | A ready-to-tweak guard config. |
| `adbg_guard_start(&cfg)` | Start the background guard thread. |
| `adbg_guard_stop()` | Stop the guard (blocks until it exits). |
| `adbg_guard_running()` | `1` if the guard is active. |

Full header: [`include/antidbg/antidbg.h`](include/antidbg/antidbg.h).

**Choosing techniques for the guard.** By default the guard runs everything.
The host-wide tool scan (`ADBG_ANALYSIS_TOOL`) can fire on a developer's own
machine, so to run every check *except* that one:

```c
adbg_guard_config cfg = adbg_guard_default();
cfg.on_detected = on_debugger;
cfg.techniques  = ~ADBG_ANALYSIS_TOOL;   // all bits except the tool scan
adbg_guard_start(&cfg);
```

## How it works

See **[docs/TECHNIQUES.md](docs/TECHNIQUES.md)** for the full table of techniques
per platform and how each can be bypassed.

## Scope and limitations

Anti-debugging is **deterrence, not DRM**. It raises the cost of reversing or
tampering with your software; it does not make either impossible. A determined
analyst with a kernel debugger or a patched loader can defeat any user-mode
check. Use `antidbg` as **one layer** in a defense-in-depth strategy — alongside
integrity checks, obfuscation, and server-side validation — not as the only lock
on the door.

Intended for **protecting software you own or are authorized to protect**.

## Layout

```
antidbg/
├── include/antidbg/antidbg.h   # public API (start here)
├── src/                        # core + per-platform backends
├── examples/                   # basic.c, protect.c
├── tests/                      # dependency-free self-tests
├── bindings/python/            # ctypes wrapper
└── docs/TECHNIQUES.md          # technique reference
```

## License

MIT — see [LICENSE](LICENSE).
