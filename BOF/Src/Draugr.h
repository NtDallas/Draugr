#pragma once

#include "Native.h"
#include "Vulcan.h"
#include "VxTable.h"

BOOL	InitVxTable(
	_Inout_	PVX_TABLE	VxTable
);

BOOL	DraugrInit(
	_Inout_	PSYNTHETIC_STACK_FRAME	SyntheticStackFrame
);

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
);
