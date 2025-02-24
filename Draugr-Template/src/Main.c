#include <windows.h>

#include "Prototypes.h"
#include "Beacon.h"
#include "Vulcan.h"
#include "Ntdll.h"
#include "Macros.h"
#include "Bofdefs.h"
#include "Syscalls.h"

#define NO_SYCALL	NULL

void go(char *args, int alen) 
{

	SYNTHETIC_STACK_FRAME   stackFrame = { 0 };
	NT_FUNC					ntFunc		= { 0 };

	if (!InitNtFunc(&ntFunc))
	{
		BeaconPrintf(CALLBACK_OUTPUT, "[!] Fail to solve SSN !\n");
		return;
	}

	if (!InitFrameInfo(&stackFrame))
	{
		BeaconPrintf(CALLBACK_OUTPUT,"[!] Fail to init stack frame !\n");
		return;
	}

	void* pVirtualAlloc = GetProcAddress(GetModuleHandleA("Kernel32.dll"), "VirtualAlloc");
	void* pVirtualFree  = GetProcAddress(GetModuleHandleA("Kernel32.dll"), "VirtualFree");

	if(!pVirtualAlloc || !pVirtualFree)
	{
		BeaconPrintf(CALLBACK_ERROR, "Can't solve function addr !\n\tVirtualAlloc : %p\n\tVirtualFree : %p", pVirtualAlloc, pVirtualFree);
		return;
	}

    LPVOID lpAddressNtAlloc 		= NULL;
	LPVOID lpAddressVirtualAlloc 	= NULL;
    SIZE_T sDataSize 				= 0x1000;

  	NTSTATUS status = SPOOF_CALL(&stackFrame, ntFunc.NtAllocateVirtualMemory.pJmpAddr, ntFunc.NtAllocateVirtualMemory.wSyscall, (HANDLE)-1, &lpAddressNtAlloc, 0, &sDataSize, MEM_COMMIT, PAGE_READWRITE);
	if(NT_ERROR(status))
	{
		BeaconPrintf(CALLBACK_ERROR, "NtAllocateVirtualMemory ERROR ! Status 0x%llx", status);
		return;
	}
    BeaconPrintf(CALLBACK_OUTPUT, "Allocated addr  with NtAllocateVirtualMemory : %p", lpAddressNtAlloc);

	lpAddressVirtualAlloc = SPOOF_CALL(&stackFrame, pVirtualAlloc, NO_SYCALL, NULL, 0x1000, MEM_COMMIT, PAGE_READWRITE);
	if(!lpAddressVirtualAlloc)
	{
		BeaconPrintf(CALLBACK_ERROR, "VirtualAlloc ERROR ! Error : %d", GetLastError());
		return;	
	}
	BeaconPrintf(CALLBACK_OUTPUT, "Allocated addr with VirtualAlloc : %p", lpAddressVirtualAlloc);

	if(!
		SPOOF_CALL(&stackFrame, pVirtualFree, NO_SYCALL, lpAddressNtAlloc, 0, MEM_RELEASE)
	)
	{
		BeaconPrintf(CALLBACK_ERROR, "Can't free virtual memory ! ERROR : %d", GetLastError());
		return;
	}

	if(!
		SPOOF_CALL(&stackFrame, pVirtualFree, NO_SYCALL, lpAddressVirtualAlloc, 0, MEM_RELEASE)
	)
	{
		BeaconPrintf(CALLBACK_ERROR, "Can't free virtual memory ! ERROR : %d", GetLastError());
		return;
	}

	BeaconPrintf(CALLBACK_OUTPUT, "All memory allocated is free with success !");
}