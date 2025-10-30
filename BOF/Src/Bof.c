#include <windows.h>
#include <stdio.h>

#include "Native.h"
#include "Vulcan.h"
#include "VxTable.h"
#include "Macros.h"
#include "Draugr.h"
#include "Beacon.h"

void go(char *args, int alen) {

	VX_TABLE				VxTable = { 0 };
	SYNTHETIC_STACK_FRAME	SyntheticStackframe = { 0 };

	if (!InitVxTable(&VxTable)) {
		BeaconPrintf(CALLBACK_ERROR, "Error during InitVxTable !");
		return;
	}

	if (!DraugrInit(&SyntheticStackframe)) {
		BeaconPrintf(CALLBACK_ERROR, "Error during DraugrInit !");
		return;
	}

	SIZE_T	AllocationSize = 0x1000;
	PVOID	AllocatedAddr = NULL;
	NTSTATUS	Status = 0;

	Status = (NTSTATUS)DRAUGR_SYSCALL(NtAllocateVirtualMemory, NtCurrentProcess, &AllocatedAddr, 0, &AllocationSize, MEM_COMMIT, PAGE_READWRITE);
	if (NT_ERROR(Status)) {
		BeaconPrintf(CALLBACK_ERROR, "Can't allocate memory ! STATUS : 0x%llx\n", Status);
		return;
	}
	else {
		BeaconPrintf(CALLBACK_OUTPUT, "Memory allocated with success ! Address : %p\n", AllocatedAddr);
	}

	PVOID	pLoadLibraryA = GetProcAddress(GetModuleHandleA("Kernel32.dll"), "LoadLibraryA");
	if(!pLoadLibraryA) {
		BeaconPrintf(CALLBACK_ERROR, "Can't resolve LoadLibraryA !");
		return;
	}

	HMODULE	hUser32 = DRAUGR_API(pLoadLibraryA, "User32.dll");
	if(!hUser32) {
		BeaconPrintf(CALLBACK_ERROR, "Can't load User32.dll !");
		return;	
	}

	BeaconPrintf(CALLBACK_OUTPUT, "User32.dll addr : %p\n", hUser32);

	PVOID pMessageBoxA = GetProcAddress(hUser32, "MessageBoxA");
	if(!pMessageBoxA) {
		BeaconPrintf(CALLBACK_ERROR, "Can't resolve MessageBoxA !");
		return;
	}

	BYTE bTitle[] = "Hello, World!";
	BYTE bText[]  = "This call to MessageBoxA has a synthetic stack frame!";

	DRAUGR_API(pMessageBoxA, NULL, bText, bTitle, MB_OK);
	return;
}
