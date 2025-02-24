#pragma once

#include <windows.h>

typedef struct _NT_CALL
{
    DWORD wSyscall;
    PVOID pJmpAddr;
} NT_CALL, *PNT_CALL;

typedef struct _NT_FUNC
{
    NT_CALL NtOpenProcess;
    NT_CALL NtAllocateVirtualMemory;
    NT_CALL NtWriteVirtualMemory;
    NT_CALL NtClose;
    NT_CALL NtProtectVirtualMemory;
    NT_CALL NtGetContextThread;
    NT_CALL NtSetContextThread;
    NT_CALL NtResumeThread;
    NT_CALL NtQueueApcThread;
    NT_CALL NtCreateThreadEx;
} NT_FUNC, *PNT_FUNC;

