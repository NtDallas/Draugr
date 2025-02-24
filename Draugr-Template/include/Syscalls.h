#pragma once

#include <windows.h>

typedef struct _NT_CALL {
    DWORD   wSyscall;
    PVOID   pJmpAddr;
} NT_CALL, * PNT_CALL;

typedef struct _NT_FUNC {
    NT_CALL NtAllocateVirtualMemory;
} NT_FUNC, * PNT_FUNC;