"""
antidbg - Python binding (ctypes) for the antidbg shared library.

Build the shared library first:

    cmake -B build -DANTIDBG_SHARED=ON
    cmake --build build

Then, from Python:

    import antidbg
    if antidbg.detected():
        print("running under a debugger!")

    # Or continuous protection:
    def on_debugger(flags):
        print("detected:", antidbg.flags_to_string(flags))
        os._exit(1)
    antidbg.guard_start(on_debugger, interval_ms=500)

This is a thin wrapper; the real detection lives in the compiled C library,
so it inspects the *Python interpreter* process it is loaded into.
"""
from __future__ import annotations

import ctypes
import os
import sys
from ctypes import c_char_p, c_int, c_uint, c_size_t, c_void_p, CFUNCTYPE

__all__ = [
    "detected", "scan", "flags_to_string",
    "guard_start", "guard_stop", "guard_running",
    "Flags", "AntidbgError",
]


class AntidbgError(RuntimeError):
    """Raised when the antidbg shared library cannot be located or loaded."""


class Flags:
    """Detection technique bit flags (mirror of the C ADBG_* constants)."""
    NONE = 0
    API_PRESENT = 1 << 0
    API_REMOTE = 1 << 1
    PEB_FLAG = 1 << 2
    PEB_NTGLOBALFLAG = 1 << 3
    DEBUG_PORT = 1 << 4
    DEBUG_FLAGS = 1 << 5
    DEBUG_OBJECT = 1 << 6
    HARDWARE_BREAKPOINT = 1 << 7
    TIMING = 1 << 8
    PARENT = 1 << 9
    TRACER = 1 << 10


def _candidate_names() -> list[str]:
    if sys.platform.startswith("win"):
        return ["antidbg.dll"]
    if sys.platform == "darwin":
        return ["libantidbg.dylib", "libantidbg.1.dylib"]
    return ["libantidbg.so", "libantidbg.so.1"]


def _load_library() -> ctypes.CDLL:
    override = os.environ.get("ANTIDBG_LIBRARY")
    search: list[str] = [override] if override else []

    here = os.path.dirname(os.path.abspath(__file__))
    roots = [
        here,
        os.path.join(here, "..", "..", "build"),
        os.path.join(here, "..", "..", "build", "Release"),
        os.path.join(here, "..", "..", "build", "Debug"),
        os.getcwd(),
    ]
    for root in roots:
        for name in _candidate_names():
            search.append(os.path.join(root, name))
    # Also let the OS loader search its default paths by bare name.
    search.extend(_candidate_names())

    last_err: Exception | None = None
    for path in search:
        if not path:
            continue
        try:
            return ctypes.CDLL(path)
        except OSError as exc:  # not found / wrong arch
            last_err = exc

    raise AntidbgError(
        "could not load the antidbg shared library. Build it with "
        "`cmake -B build -DANTIDBG_SHARED=ON && cmake --build build`, or set "
        "the ANTIDBG_LIBRARY environment variable to its path. "
        f"(last error: {last_err})"
    )


_lib = _load_library()

# ---- prototypes ----------------------------------------------------------
_lib.adbg_scan.restype = c_uint
_lib.adbg_scan.argtypes = []

_lib.adbg_detected.restype = c_int
_lib.adbg_detected.argtypes = []

_lib.adbg_flags_to_string.restype = c_size_t
_lib.adbg_flags_to_string.argtypes = [c_uint, c_char_p, c_size_t]

_GUARD_CB = CFUNCTYPE(None, c_uint, c_void_p)


class _GuardConfig(ctypes.Structure):
    _fields_ = [
        ("interval_ms", c_uint),
        ("techniques", c_uint),
        ("on_detected", _GUARD_CB),
        ("user", c_void_p),
        ("oneshot", c_int),
    ]


_lib.adbg_guard_start.restype = c_int
_lib.adbg_guard_start.argtypes = [ctypes.POINTER(_GuardConfig)]
_lib.adbg_guard_stop.restype = None
_lib.adbg_guard_stop.argtypes = []
_lib.adbg_guard_running.restype = c_int
_lib.adbg_guard_running.argtypes = []

# Keep the active callback alive so the GC doesn't free the trampoline.
_active_cb: "_GUARD_CB | None" = None


# ---- public API ----------------------------------------------------------
def scan() -> int:
    """Run all detection techniques once; return the combined flag mask."""
    return int(_lib.adbg_scan())


def detected() -> bool:
    """True if a debugger was detected."""
    return bool(_lib.adbg_detected())


def flags_to_string(flags: int) -> str:
    """Human-readable, comma-separated names for the set bits in `flags`."""
    buf = ctypes.create_string_buffer(256)
    _lib.adbg_flags_to_string(c_uint(flags), buf, c_size_t(len(buf)))
    return buf.value.decode("ascii", "replace")


def guard_start(on_detected, interval_ms: int = 750,
                techniques: int = 0, oneshot: bool = False) -> None:
    """
    Start the background guard. `on_detected(flags: int)` is called from the
    guard thread when a debugger is spotted. Raises AntidbgError on failure.
    """
    global _active_cb

    def _trampoline(flags: int, _user: int) -> None:
        on_detected(int(flags))

    _active_cb = _GUARD_CB(_trampoline)
    cfg = _GuardConfig(
        interval_ms=c_uint(interval_ms),
        techniques=c_uint(techniques),
        on_detected=_active_cb,
        user=None,
        oneshot=c_int(1 if oneshot else 0),
    )
    rc = _lib.adbg_guard_start(ctypes.byref(cfg))
    if rc != 0:
        _active_cb = None
        raise AntidbgError(f"adbg_guard_start failed (code {rc})")


def guard_stop() -> None:
    """Stop the background guard and wait for it to exit."""
    global _active_cb
    _lib.adbg_guard_stop()
    _active_cb = None


def guard_running() -> bool:
    """True if the guard thread is currently running."""
    return bool(_lib.adbg_guard_running())


if __name__ == "__main__":
    f = scan()
    print("detected" if f else "clean", "->", flags_to_string(f))
    sys.exit(1 if f else 0)
