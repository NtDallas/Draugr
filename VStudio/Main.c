#include <Windows.h>
#include <stdio.h>

#include "Native.h"
#include "Vulcan.h"
#include "VxTable.h"
#include "Macros.h"
#include "Draugr.h"


int main() {

	VX_TABLE				VxTable = { 0 };
	SYNTHETIC_STACK_FRAME	SyntheticStackframe = { 0 };

	if (!InitVxTable(&VxTable)) {
		return EXIT_FAILURE;
	}

	if (!DraugrInit(&SyntheticStackframe)) {
		return EXIT_FAILURE;
	}

	SIZE_T	AllocationSize = 0x1000;
	PVOID	AllocatedAddr = NULL;
	NTSTATUS	Status = 0;

	BYTE bTitle[] = "Hello World";
	BYTE bText[] = "This call of MessageBoxA have a synthetic stackframe !";

	DRAUGR_API(MessageBoxA, NULL, bText, bTitle, MB_OK);

	Status = DRAUGR_SYSCALL(NtAllocateVirtualMemory, NtCurrentProcess, &AllocatedAddr, 0, &AllocationSize, MEM_COMMIT, PAGE_READWRITE);
	if (NT_ERROR(Status)) {
		printf("[!] Can't allocate memory ! STATUS : 0x%llx\n", Status);
		return EXIT_FAILURE;
	}
	else {
		printf("[*] Memory allocated with success ! Address : %p\n", AllocatedAddr);
	}

	return EXIT_SUCCESS;
}