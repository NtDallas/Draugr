#pragma once

#include "Native.h"

typedef struct _VX_TABLE_ENTRY {
	PVOID	Gadget;
	DWORD	SyscallNumber;
} VX_TABLE_ENTRY, *PVX_TABLE_ENTRY;

typedef struct _VX_TABLE {
	VX_TABLE_ENTRY	NtAllocateVirtualMemory;
	VX_TABLE_ENTRY	NtWriteVirtualMemory;
	VX_TABLE_ENTRY	NtProtectVirtualMemory;
	VX_TABLE_ENTRY	NtCreateThreadEx;
} VX_TABLE, *PVX_TABLE;
