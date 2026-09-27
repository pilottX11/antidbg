/*
 * basic.c - one-shot detection.
 *
 * Build (with the library already built via CMake), or just compile the
 * sources directly:
 *
 *   cc -I../include basic.c ../src/antidbg.c ../src/antidbg_*.c -o basic
 *
 * Run it normally: prints "clean". Run it under gdb/x64dbg/WinDbg: prints
 * which techniques fired.
 */
#include <antidbg/antidbg.h>
#include <stdio.h>

int main(void)
{
    adbg_flags flags = adbg_scan();
    char names[256];

    adbg_flags_to_string(flags, names, sizeof(names));

    if (flags == ADBG_NONE) {
        printf("clean: no debugger detected\n");
        return 0;
    }

    printf("debugger detected! techniques: %s\n", names);
    return 1;
}
