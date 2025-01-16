#include <windows.h>

DECLSPEC_IMPORT	PRUNTIME_FUNCTION WINAPI	KERNEL32$RtlLookupFunctionEntry(DWORD64 ControlPc, PDWORD64 ImageBase,PUNWIND_HISTORY_TABLE HistoryTable);
DECLSPEC_IMPORT	HMODULE WINAPI	            KERNEL32$GetModuleHandleA(LPCSTR lpModuleName);
DECLSPEC_IMPORT FARPROC WINAPI 	            KERNEL32$GetProcAddress(HMODULE hModule, LPCSTR lpProcName);

DECLSPEC_IMPORT ULONG NTAPI 	            NTDLL$RtlRandomEx(PULONG seed);

DECLSPEC_IMPORT PCHAR __cdecl 	            MSVCRT$strcmp(const char* str1, const char* str2);

#define RtlLookupFunctionEntry  KERNEL32$RtlLookupFunctionEntry
#define GetModuleHandleA        KERNEL32$GetModuleHandleA
#define GetProcAddress          KERNEL32$GetProcAddress

#define RtlRandomEx             NTDLL$RtlRandomEx

#define strcmp                  MSVCRT$strcmp