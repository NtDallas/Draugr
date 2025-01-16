#include <windows.h>

#include "Prototypes.h"
#include "Beacon.h"
#include "Vulcan.h"
#include "Ntdll.h"
#include "Macros.h"
#include "Bofdefs.h"

void go(char *args, int alen) 
{

	SYNTHETIC_STACK_FRAME   stackFrame = { 0 };
	if (!InitFrameInfo(&stackFrame))
	{
		BeaconPrintf(CALLBACK_OUTPUT,"[!] Fail to init stack frame !\n");
	}

	HMODULE pKernel32 = GetModuleHandleA("Kernel32.dll");

	void* pVirtualALloc = (void*)GetProcAddress(pKernel32, "VirtualAlloc");

	for (int i = 0; i < 10; i++)
	{
		void *pAllocatedAddr = SPOOF_CALL(&stackFrame, pVirtualALloc, NULL, 1024 * 1024, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		BeaconPrintf(CALLBACK_OUTPUT, "Allocated addr : %p", pAllocatedAddr);
	}
}