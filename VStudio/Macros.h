#pragma once

#define GET_NT_HEADER(x)			((PIMAGE_NT_HEADERS)((DWORD64)x + ((PIMAGE_DOS_HEADER)(x))->e_lfanew))
#define	DRAUGR_RESOLVE(NtFunction)	DraugrResolveSyscall(GetProcAddress(pNtdll,  #NtFunction), &VxTable->NtFunction.SyscallNumber, &VxTable->NtFunction.Gadget)
#define DOWN	                    32
#define SYSCALL_GADGET_OFFSET       0x12

#define DRAUGR_SYSCALL_X(Name) \
    DraugrCall(&SyntheticStackframe, VxTable.Name.Gadget, VxTable.Name.SyscallNumber, \
        NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL)

#define DRAUGR_SYSCALL_A(Name, a) \
    DraugrCall(&SyntheticStackframe, VxTable.Name.Gadget, VxTable.Name.SyscallNumber, \
        (PVOID)(a), NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL)

#define DRAUGR_SYSCALL_B(Name, a, b) \
    DraugrCall(&SyntheticStackframe, VxTable.Name.Gadget, VxTable.Name.SyscallNumber, \
        (PVOID)(a), (PVOID)(b), NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL)

#define DRAUGR_SYSCALL_C(Name, a, b, c) \
    DraugrCall(&SyntheticStackframe, VxTable.Name.Gadget, VxTable.Name.SyscallNumber, \
        (PVOID)(a), (PVOID)(b), (PVOID)(c), NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL)

#define DRAUGR_SYSCALL_D(Name, a, b, c, d) \
    DraugrCall(&SyntheticStackframe, VxTable.Name.Gadget, VxTable.Name.SyscallNumber, \
        (PVOID)(a), (PVOID)(b), (PVOID)(c), (PVOID)(d), NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL)

#define DRAUGR_SYSCALL_E(Name, a, b, c, d, e) \
    DraugrCall(&SyntheticStackframe, VxTable.Name.Gadget, VxTable.Name.SyscallNumber, \
        (PVOID)(a), (PVOID)(b), (PVOID)(c), (PVOID)(d), (PVOID)(e), NULL, NULL, NULL, NULL, NULL, NULL, NULL)

#define DRAUGR_SYSCALL_F(Name, a, b, c, d, e, f) \
    DraugrCall(&SyntheticStackframe, VxTable.Name.Gadget, VxTable.Name.SyscallNumber, \
        (PVOID)(a), (PVOID)(b), (PVOID)(c), (PVOID)(d), (PVOID)(e), (PVOID)(f), NULL, NULL, NULL, NULL, NULL, NULL)

#define DRAUGR_SYSCALL_G(Name, a, b, c, d, e, f, g) \
    DraugrCall(&SyntheticStackframe, VxTable.Name.Gadget, VxTable.Name.SyscallNumber, \
        (PVOID)(a), (PVOID)(b), (PVOID)(c), (PVOID)(d), (PVOID)(e), (PVOID)(f), (PVOID)(g), NULL, NULL, NULL, NULL, NULL)

#define DRAUGR_SYSCALL_H(Name, a, b, c, d, e, f, g, h) \
    DraugrCall(&SyntheticStackframe, VxTable.Name.Gadget, VxTable.Name.SyscallNumber, \
        (PVOID)(a), (PVOID)(b), (PVOID)(c), (PVOID)(d), (PVOID)(e), (PVOID)(f), (PVOID)(g), (PVOID)(h), NULL, NULL, NULL, NULL)

#define DRAUGR_SYSCALL_I(Name, a, b, c, d, e, f, g, h, i) \
    DraugrCall(&SyntheticStackframe, VxTable.Name.Gadget, VxTable.Name.SyscallNumber, \
        (PVOID)(a), (PVOID)(b), (PVOID)(c), (PVOID)(d), (PVOID)(e), (PVOID)(f), (PVOID)(g), (PVOID)(h), (PVOID)(i), NULL, NULL, NULL)

#define DRAUGR_SYSCALL_J(Name, a, b, c, d, e, f, g, h, i, j) \
    DraugrCall(&SyntheticStackframe, VxTable.Name.Gadget, VxTable.Name.SyscallNumber, \
        (PVOID)(a), (PVOID)(b), (PVOID)(c), (PVOID)(d), (PVOID)(e), (PVOID)(f), (PVOID)(g), (PVOID)(h), (PVOID)(i), (PVOID)(j), NULL, NULL)

#define DRAUGR_SYSCALL_K(Name, a, b, c, d, e, f, g, h, i, j, k) \
    DraugrCall(&SyntheticStackframe, VxTable.Name.Gadget, VxTable.Name.SyscallNumber, \
        (PVOID)(a), (PVOID)(b), (PVOID)(c), (PVOID)(d), (PVOID)(e), (PVOID)(f), (PVOID)(g), (PVOID)(h), (PVOID)(i), (PVOID)(j), (PVOID)(k), NULL)

#define DRAUGR_SYSCALL_L(Name, a, b, c, d, e, f, g, h, i, j, k, l) \
    DraugrCall(&SyntheticStackframe, VxTable.Name.Gadget, VxTable.Name.SyscallNumber, \
        (PVOID)(a), (PVOID)(b), (PVOID)(c), (PVOID)(d), (PVOID)(e), (PVOID)(f), (PVOID)(g), (PVOID)(h), (PVOID)(i), (PVOID)(j), (PVOID)(k), (PVOID)(l))

#define DCALL_EXPAND(x) x
#define DCALL_GET_MACRO(_1, _2, _3, _4, _5, _6, _7, _8, _9, _10, _11, _12, NAME, ...) NAME

#define DRAUGR_SYSCALL(Name, ...) \
    DCALL_EXPAND(DCALL_GET_MACRO(__VA_ARGS__, \
        DRAUGR_SYSCALL_L, DRAUGR_SYSCALL_K, DRAUGR_SYSCALL_J, DRAUGR_SYSCALL_I, \
        DRAUGR_SYSCALL_H, DRAUGR_SYSCALL_G, DRAUGR_SYSCALL_F, DRAUGR_SYSCALL_E, \
        DRAUGR_SYSCALL_D, DRAUGR_SYSCALL_C, DRAUGR_SYSCALL_B, DRAUGR_SYSCALL_A, \
        DRAUGR_SYSCALL_X)(Name, __VA_ARGS__))


#define DRAUGR_API_X(Name) \
    DraugrCall(&SyntheticStackframe, Name, 0, \
        NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL)

#define DRAUGR_API_A(Name, a) \
    DraugrCall(&SyntheticStackframe, Name, 0, \
        (PVOID)(a), NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL)

#define DRAUGR_API_B(Name, a, b) \
    DraugrCall(&SyntheticStackframe, Name, 0, \
        (PVOID)(a), (PVOID)(b), NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL)

#define DRAUGR_API_C(Name, a, b, c) \
    DraugrCall(&SyntheticStackframe, Name, 0, \
        (PVOID)(a), (PVOID)(b), (PVOID)(c), NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL)

#define DRAUGR_API_D(Name, a, b, c, d) \
    DraugrCall(&SyntheticStackframe, Name, 0, \
        (PVOID)(a), (PVOID)(b), (PVOID)(c), (PVOID)(d), NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL)

#define DRAUGR_API_E(Name, a, b, c, d, e) \
    DraugrCall(&SyntheticStackframe, Name, 0, \
        (PVOID)(a), (PVOID)(b), (PVOID)(c), (PVOID)(d), (PVOID)(e), NULL, NULL, NULL, NULL, NULL, NULL, NULL)

#define DRAUGR_API_F(Name, a, b, c, d, e, f) \
    DraugrCall(&SyntheticStackframe, Name, 0, \
        (PVOID)(a), (PVOID)(b), (PVOID)(c), (PVOID)(d), (PVOID)(e), (PVOID)(f), NULL, NULL, NULL, NULL, NULL, NULL)

#define DRAUGR_API_G(Name, a, b, c, d, e, f, g) \
    DraugrCall(&SyntheticStackframe, Name, 0, \
        (PVOID)(a), (PVOID)(b), (PVOID)(c), (PVOID)(d), (PVOID)(e), (PVOID)(f), (PVOID)(g), NULL, NULL, NULL, NULL, NULL)

#define DRAUGR_API_H(Name, a, b, c, d, e, f, g, h) \
    DraugrCall(&SyntheticStackframe, Name, 0, \
        (PVOID)(a), (PVOID)(b), (PVOID)(c), (PVOID)(d), (PVOID)(e), (PVOID)(f), (PVOID)(g), (PVOID)(h), NULL, NULL, NULL, NULL)

#define DRAUGR_API_I(Name, a, b, c, d, e, f, g, h, i) \
    DraugrCall(&SyntheticStackframe, Name, 0, \
        (PVOID)(a), (PVOID)(b), (PVOID)(c), (PVOID)(d), (PVOID)(e), (PVOID)(f), (PVOID)(g), (PVOID)(h), (PVOID)(i), NULL, NULL, NULL)

#define DRAUGR_API_J(Name, a, b, c, d, e, f, g, h, i, j) \
    DraugrCall(&SyntheticStackframe, Name, 0, \
        (PVOID)(a), (PVOID)(b), (PVOID)(c), (PVOID)(d), (PVOID)(e), (PVOID)(f), (PVOID)(g), (PVOID)(h), (PVOID)(i), (PVOID)(j), NULL, NULL)

#define DRAUGR_API_K(Name, a, b, c, d, e, f, g, h, i, j, k) \
    DraugrCall(&SyntheticStackframe, Name, 0, \
        (PVOID)(a), (PVOID)(b), (PVOID)(c), (PVOID)(d), (PVOID)(e), (PVOID)(f), (PVOID)(g), (PVOID)(h), (PVOID)(i), (PVOID)(j), (PVOID)(k), NULL)

#define DRAUGR_API_L(Name, a, b, c, d, e, f, g, h, i, j, k, l) \
    DraugrCall(&SyntheticStackframe, Name, 0, \
        (PVOID)(a), (PVOID)(b), (PVOID)(c), (PVOID)(d), (PVOID)(e), (PVOID)(f), (PVOID)(g), (PVOID)(h), (PVOID)(i), (PVOID)(j), (PVOID)(k), (PVOID)(l))

#define DRAUGR_API_EXPAND(x) x
#define DRAUGR_API_GET_MACRO(_1, _2, _3, _4, _5, _6, _7, _8, _9, _10, _11, _12, NAME, ...) NAME

#define DRAUGR_API(Name, ...) \
    DRAUGR_API_EXPAND(DRAUGR_API_GET_MACRO(__VA_ARGS__, \
        DRAUGR_API_L, DRAUGR_API_K, DRAUGR_API_J, DRAUGR_API_I, \
        DRAUGR_API_H, DRAUGR_API_G, DRAUGR_API_F, DRAUGR_API_E, \
        DRAUGR_API_D, DRAUGR_API_C, DRAUGR_API_B, DRAUGR_API_A, \
        DRAUGR_API_X)(Name, __VA_ARGS__))
