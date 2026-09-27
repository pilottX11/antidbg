/* antidbg - internal declarations shared between core and platform backends. */
#ifndef ANTIDBG_INTERNAL_H
#define ANTIDBG_INTERNAL_H

#include "antidbg/antidbg.h"

/*
 * Platform backend entry point. Runs the platform-specific detection
 * techniques and returns the combined flag mask. Implemented once per
 * platform in antidbg_windows.c / antidbg_linux.c / antidbg_macos.c.
 */
adbg_flags adbg_platform_scan(void);

/*
 * Scan the host for running reverse-engineering tools (IDA, x64dbg, Ghidra,
 * Binary Ninja, Cutter, dnSpy, Process Hacker, ...). Cross-platform; returns
 * ADBG_ANALYSIS_TOOL if any is found, else ADBG_NONE. Implemented once in
 * antidbg_tools.c with platform-specific enumeration inside.
 */
adbg_flags adbg_scan_tools(void);

#endif /* ANTIDBG_INTERNAL_H */
