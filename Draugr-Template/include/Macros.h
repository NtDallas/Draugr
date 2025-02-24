#define D_SEC( x )  __attribute__( ( section( ".text$" #x "" ) ) )

#define SPOOF_CALL_X(stackFrame, function, dwSyscall) \
    SpoofCall(stackFrame, (PVOID)(function),  dwSyscall, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL)

#define SPOOF_CALL_A(stackFrame, function, dwSyscall, a) \
    SpoofCall(stackFrame, (PVOID)(function),  dwSyscall, (PVOID)(a), NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL)

#define SPOOF_CALL_B(stackFrame, function, dwSyscall, a, b) \
    SpoofCall(stackFrame, (PVOID)(function),  dwSyscall, (PVOID)(a), (PVOID)(b), NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL)

#define SPOOF_CALL_C(stackFrame, function, dwSyscall, a, b, c) \
    SpoofCall(stackFrame, (PVOID)(function),  dwSyscall, (PVOID)(a), (PVOID)(b), (PVOID)(c), NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL)

#define SPOOF_CALL_D(stackFrame, function, dwSyscall, a, b, c, d) \
    SpoofCall(stackFrame, (PVOID)(function),  dwSyscall, (PVOID)(a), (PVOID)(b), (PVOID)(c), (PVOID)(d), NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL)

#define SPOOF_CALL_E(stackFrame, function, dwSyscall, a, b, c, d, e) \
    SpoofCall(stackFrame, (PVOID)(function),  dwSyscall, (PVOID)(a), (PVOID)(b), (PVOID)(c), (PVOID)(d), (PVOID)(e), NULL, NULL, NULL, NULL, NULL, NULL, NULL)

#define SPOOF_CALL_F(stackFrame, function, dwSyscall, a, b, c, d, e, f) \
    SpoofCall(stackFrame, (PVOID)(function),  dwSyscall, (PVOID)(a), (PVOID)(b), (PVOID)(c), (PVOID)(d), (PVOID)(e), (PVOID)(f), NULL, NULL, NULL, NULL, NULL, NULL)

#define SPOOF_CALL_G(stackFrame, function, dwSyscall, a, b, c, d, e, f, g) \
    SpoofCall(stackFrame, (PVOID)(function),  dwSyscall, (PVOID)(a), (PVOID)(b), (PVOID)(c), (PVOID)(d), (PVOID)(e), (PVOID)(f), (PVOID)(g), NULL, NULL, NULL, NULL, NULL)

#define SPOOF_CALL_H(stackFrame, function, dwSyscall, a, b, c, d, e, f, g, h) \
    SpoofCall(stackFrame, (PVOID)(function),  dwSyscall, (PVOID)(a), (PVOID)(b), (PVOID)(c), (PVOID)(d), (PVOID)(e), (PVOID)(f), (PVOID)(g), (PVOID)(h), NULL, NULL, NULL, NULL)

#define SPOOF_CALL_I(stackFrame, function, dwSyscall, a, b, c, d, e, f, g, h, i) \
    SpoofCall(stackFrame, (PVOID)(function),  dwSyscall, (PVOID)(a), (PVOID)(b), (PVOID)(c), (PVOID)(d), (PVOID)(e), (PVOID)(f), (PVOID)(g), (PVOID)(h), (PVOID)(i), NULL, NULL, NULL)

#define SPOOF_CALL_J(stackFrame, function, dwSyscall, a, b, c, d, e, f, g, h, i, j) \
    SpoofCall(stackFrame, (PVOID)(function),  dwSyscall, (PVOID)(a), (PVOID)(b), (PVOID)(c), (PVOID)(d), (PVOID)(e), (PVOID)(f), (PVOID)(g), (PVOID)(h), (PVOID)(i), (PVOID)(j), NULL, NULL)

#define SPOOF_CALL_K(stackFrame, function, dwSyscall, a, b, c, d, e, f, g, h, i, j, k) \
    SpoofCall(stackFrame, (PVOID)(function),  dwSyscall, (PVOID)(a), (PVOID)(b), (PVOID)(c), (PVOID)(d), (PVOID)(e), (PVOID)(f), (PVOID)(g), (PVOID)(h), (PVOID)(i), (PVOID)(j), (PVOID)(k), NULL)

#define SPOOF_CALL_L(stackFrame, function, dwSyscall, a, b, c, d, e, f, g, h, i, j, k, l) \
    SpoofCall(stackFrame, (PVOID)(function),  dwSyscall, (PVOID)(a), (PVOID)(b), (PVOID)(c), (PVOID)(d), (PVOID)(e), (PVOID)(f), (PVOID)(g), (PVOID)(h), (PVOID)(i), (PVOID)(j), (PVOID)(k), (PVOID)(l))

#define SPOOF_CALL_MACRO_CHOOSER(_1, _2, _3, _4, _5, _6, _7, _8, _9, _10, _11, _12, NAME, ...) NAME

#define SPOOF_CALL(stackFrame, function, dwSyscall, ...) \
    SPOOF_CALL_MACRO_CHOOSER(__VA_ARGS__, \
        SPOOF_CALL_L, SPOOF_CALL_K, SPOOF_CALL_J, SPOOF_CALL_I, \
        SPOOF_CALL_H, SPOOF_CALL_G, SPOOF_CALL_F, SPOOF_CALL_E, \
        SPOOF_CALL_D, SPOOF_CALL_C, SPOOF_CALL_B, SPOOF_CALL_A, \
        SPOOF_CALL_X)(stackFrame, function, dwSyscall, __VA_ARGS__)
