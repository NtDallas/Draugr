#include <windows.h>

#include "Vulcan.h"


 /* --------------------------------
    Utils.s
-------------------------------- */

extern void* SpoofStub(...);

 /* --------------------------------
    Spoof.c
-------------------------------- */

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
);

BOOL InitFrameInfo(
    _In_	PSYNTHETIC_STACK_FRAME	stackFrame
);