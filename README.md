# Draugr

Nowadays, some EDRs analyze the stack frame for sensitive API calls, such as memory usage. If the origin of the API call comes from an executable region that is not backed by the disk, it follows the typical shellcode pattern, and you may be detected by the EDR.

It is possible to spoof the return address to evade detection, but your stack frame may still appear suspicious because, after the gadget, there is nothing left. With this implementation, return address spoofing is used, and after the gadget, two frames are pushed to mimic a thread start.

The advantage of a synthetic stack frame is its execution speed and the ability to retrieve the return value of an API call unlike thread pool techniques, which are slower and do not allow retrieving function return values.

## Technical Implementation

### Execution Flow Overview

Draugr operates through a multi-stage process that calculates stack frame sizes, resolves syscall numbers, and constructs synthetic call stacks before executing target functions. The repos consists of three primary phases: initialization, stack frame calculation, and assembly-level execution redirection.

### Stack Spoofing Mechanism
```
Normal Execution (Without Draugr):
    User Code
        │ call NtAllocateVirtualMemory
        ▼
    ┌─────────────────────────────────┐
    │ Stack Layout:                   │
    │   [return to user code]  <─RSP  │  <- Detectable (Unbacked RX region)
    └─────────────────────────────────┘
        │
        ▼
    NtAllocateVirtualMemory executes
    Security product inspects stack, sees user code origin


Draugr Execution (Indirect Syscall + Spoofed Stack):
    User Code
        │ DRAUGR_SYSCALL(NtAllocateVirtualMemory, ...)
        ▼
    DraugrCall() → Spoof()
        │
        ├─ Calculate: BTIT stack size = 0x38
        ├─ Calculate: RUTS stack size = 0x58  
        ├─ Calculate: Gadget stack size = 0x28
        └─ Find: jmp [rbx] gadget in kernelbase.dll
        │
        ▼
    ┌─────────────────────────────────────────────────────┐
    │ Synthetic Stack Construction:                       │
    │                                                     │
    │   High Address                                      │
    │   ┌──────────────────────────────┐                  │
    │   │ Reserved Space (0x200)       │                  │
    │   ├──────────────────────────────┤                  │
    │   │ RUTS Stack Space (0x58)      │                  │
    │   │ [RtlUserThreadStart+0x21] ◄──┼─── Fabricated    │
    │   ├──────────────────────────────┤                  │
    │   │ BTIT Stack Space (0x38)      │                  │
    │   │ [BaseThreadInitThunk+0x14] ◄─┼─── Fabricated    │
    │   ├──────────────────────────────┤                  │
    │   │ Gadget Stack Space (0x28)    │                  │
    │   │ [jmp [rbx] in kernelbase] ◄──┼─── Return addr   │
    │   └──────────────────────────────┘ <─RSP            │
    │   Low Address                                       │
    └─────────────────────────────────────────────────────┘
        │
        ├─ Set: RAX = syscall number (0x0018)
        ├─ Set: R10 = first argument
        ├─ Set: RBX = &PRM (contains fixup address at offset 0x00)
        │
        ▼
    jmp r11 (r11 = syscall instruction address in ntdll)
        │
        ▼
    syscall instruction executes
        │
        ▼
    Kernel Mode Execution
        │
        ▼
    ret (returns to [RSP] = jmp [rbx] gadget)
        │
        ▼
    Gadget: jmp [rbx]  (rbx points to PRM.Fixup)
        │
        ▼
    Fixup routine
        │
        ├─ Deallocate synthetic frames
        ├─ Restore registers
        └─ jmp to original return address
        │
        ▼
    User Code (continues normally)


Security Product View During Syscall:
    Call Stack Inspection:
    ┌────────────────────────────────────┐
    │ [0] ntdll!NtAllocateVirtualMemory  │
    │ [1] ntdll!RtlUserThreadStart+0x21  │ <- Appears legitimate
    │ [2] kernel32!BaseThreadInitThunk   │ <- Appears legitimate  
    └────────────────────────────────────┘
    Detection evaded: No suspicious user code in call stack
```

### Phase 1: Initialization and Resolution

The `DraugrInit` function establishes the synthetic stack frame structure by resolving addresses of legitimate Windows functions. It queries module handles for `kernel32.dll`, `ntdll.dll`, and `kernelbase.dll`, then retrieves function pointers for `KERNEL32!BaseThreadInitThunk` and `NTDLL!RtlUserThreadStart`. These functions are selected because they naturally appear in legitimate call stacks as part of thread initialization, providing cover for the spoofed frames. The framework stores these function addresses along with predetermined offsets (0x14 for BaseThreadInitThunk, 0x21 for RtlUserThreadStart) that point to locations within those functions where CALL instructions exist, ensuring return addresses appear valid during stack inspection.

`InitVxTable` resolves syscall numbers through the `DraugrResolveSyscall` function, which implements a two-phase approach. First, it attempts direct pattern matching at the function entry point, searching for the byte sequence `4C 8B D1 B8 XX XX 00 00` (mov r10, rcx; mov eax, syscall_number). If this pattern is not found, indicating the function has been hooked, the algorithm performs a neighbor search by examining functions at 32-byte intervals (the standard NT function stub size) up to 500 iterations. This technique exploits the fact that NT functions are sequentially ordered in `ntdll.dll` with monotonically increasing syscall numbers. The extracted syscall number and gadget address (function+0x12, pointing to the syscall instruction) are stored in the `VX_TABLE` structure for later use.

### Phase 2: Stack Frame Size Calculation

Before constructing synthetic frames, Draugr must determine the exact stack space required by each function in the call chain. The `DraugrWrapperStackSize` function invokes `NTDLL!RtlLookupFunctionEntry` to retrieve the `RUNTIME_FUNCTION` entry for a given address, which contains a pointer to the function's `UNWIND_INFO` structure. This metadata, stored in the PE file's .pdata section, describes the function's prologue operations for exception handling purposes.

`DraugrCalculateStackSize` parses the `UNWIND_CODE` array within `UNWIND_INFO`, iterating through each unwind operation to accumulate stack allocations. The algorithm handles five operation types: `UWOP_PUSH_NONVOL` adds 8 bytes per register push, `UWOP_ALLOC_SMALL` decodes allocations of 8-128 bytes using the formula `(OpInfo * 8) + 8`, `UWOP_ALLOC_LARGE` handles larger allocations by reading additional slots with scaling factors, `UWOP_SET_FPREG` is ignored as it only affects register state, and `UWOP_SAVE_NONVOL` increments the index to skip offset data without adding to stack size. For functions with chained unwind information (indicated by `UNW_FLAG_CHAININFO`), the function recursively processes the linked `RUNTIME_FUNCTION` structure. The final calculation adds 8 bytes for the return address, producing the total stack frame size required to accurately reconstruct that function's frame.

### Phase 3: Gadget Discovery and Validation

`DraugrFindGadget` locates executable code sequences that enable indirect control transfer. The function retrieves the .text section boundaries using PE header parsing, then performs a linear scan searching for the byte pattern `0xFF 0x23`, which corresponds to the x64 instruction jmp [rbx]. This instruction is crucial because it dereferences the value in RBX and transfers control to that address, allowing the framework to redirect execution back to the cleanup routine. The gadget serves as a return address on the synthetic stack, ensuring that when the syscall completes, execution transfers through the gadget to the fixup code rather than returning directly to user code.

### Phase 4: Assembly Execution and Stack Manipulation

The Spoof assembly routine in `Stub.s` performs the actual stack frame fabrication and control transfer. Upon entry, it preserves non-volatile registers (RDI, RSI, R12-R15) by saving them into the `PRM` structure, which serves as a parameter block containing all information needed for synthetic frame construction. The routine then copies stack arguments (parameters beyond the first four) from the original stack to their destination in the synthetic frame, calculating destination offsets based on the accumulated stack sizes from Phase 2.

Stack frame construction allocates space in three layers. First, 512 bytes (0x200) of reserved space provides a buffer. Then, for each function in the chain (`NTDLL!RtlUserThreadStart`, `KERNEL32!BaseThreadInitThunk`, and the `gadget`), the routine subtracts the calculated stack size from RSP and writes the corresponding return address at the stack pointer. The bottom-most return address is the jmp [rbx] gadget address, which will be used when the syscall returns. Above that are the fabricated return addresses to `KERNEL32!BaseThreadInitThunk+0x14` and `NTDLL!RtlUserThreadStart+0x21`, creating the appearance of a legitimate call chain.

Before executing the syscall, the routine sets up the execution context. RAX receives the syscall number from `PRM.ssn`, R10 receives the first argument (syscall calling convention requirement), and RBX is set to point to the PRM structure. The fixup routine address is stored at `PRM.Fixup` (offset 0x00), so when the gadget executes `jmp [rbx]`, it will dereference PRM and jump to the cleanup code. The routine then performs jmp r11, where R11 contains the syscall instruction address from the `PRM.ssn`.

### Phase 5: Return and Cleanup

When the syscall completes, it executes ret, which pops the top stack value and jumps to it. This value is the `jmp [rbx]` gadget address placed during stack construction. The gadget executes, dereferencing RBX (which points to `PRM.Fixup`) and jumping to the fixup routine. The fixup routine deallocates the synthetic stack frames by adding the calculated sizes back to RSP, restores all preserved non-volatile registers from the PRM structure, and finally jumps to PRM.OG_retaddr, which contains the original return address saved at the beginning of Spoof. This returns control to the calling function as if the spoofing never occurred, maintaining program execution flow while leaving no artifacts on the stack.

### Macro Interface

The `DRAUGR_SYSCALL` and `DRAUGR_API` macros provide a clean abstraction over this complex mechanism. Using variadic macro techniques with argument counting, they select the appropriate specialized macro (DRAUGR_SYSCALL_A through DRAUGR_SYSCALL_L) based on the number of arguments, automatically filling unused argument slots with NULL. `DRAUGR_SYSCALL` references the `VX_TABLE` to retrieve the syscall number and gadget address, while `DRAUGR_API` passes the function pointer directly with a zero syscall number. Both macros ultimately invoke `DraugrCall` with a complete argument set, hiding the complexity of PRM structure population and Spoof invocation from the caller.

### Integration Example

A complete invocation sequence demonstrates the integration: DRAUGR_SYSCALL(NtAllocateVirtualMemory, ...) expands to `DraugrCall` with `VxTable.NtAllocateVirtualMemory.Gadget` and `VxTable.NtAllocateVirtualMemory.SyscallNumber`. `DraugrCall` calculates stack sizes for `KERNEL32!BaseThreadInitThunk`, `NTDLL!RtlUserThreadStart`, and the gadget, locates a jmp [rbx] gadget in `kernelbase.dll`, populates the `PRM` structure with all calculated values and arguments, then invokes Spoof. The assembly routine constructs three synthetic stack frames, sets RAX to the syscall number, jumps directly to the syscall instruction, executes the kernel transition, returns to the jmp [rbx] gadget, transfers through the gadget to the fixup routine, and ultimately returns the syscall result to the original caller. Throughout this process, any stack walker observing the call stack during syscall execution sees return addresses pointing to `NTDLL!RtlUserThreadStart` and `KERNEL32!BaseThreadInitThunk` rather than the actual calling code, successfully masking the execution origin.

# Block Draugr : Hardware-Based Mitigation

## Shadow Stack Mitigation

Control-flow Enforcement Technology (CET) is a hardware-based security feature that maintains a parallel **shadow stack** to **validate return addresses**. The processor automatically pushes return addresses to both the regular stack (RSP) and the shadow stack (SSP) during CALL instructions, then compares them during RET instructions. Any mismatch triggers a Control Protection exception (#CP), terminating the process.

### CET Detection of Draugr

Draugr is **fundamentally incompatible with CET** because it manually writes synthetic return addresses to the regular stack using MOV instructions, which do not update the shadow stack. The divergence occurs immediately during stack frame construction:
```
Draugr Stack Manipulation (Phase 1: Spoof Routine):

Regular Stack (RSP):              Shadow Stack (SSP):          CET Status:
┌─────────────────────┐          ┌─────────────────────┐
│ [BTIT+0x14]         │ (MOV)    │ [ret DraugrCall]    │      DESYNCHRONIZED
├─────────────────────┤          ├─────────────────────┤
│ [RUTS+0x21]         │ (MOV)    │ [ret DRAUGR_SYSCALL]│      Stack mismatch
├─────────────────────┤          ├─────────────────────┤
│ [ret DraugrCall]    │ (CALL)   │ [ret main]          │      created
└─────────────────────┘          └─────────────────────┘

When syscall executes RET:
    1. Processor reads: RSP -> BaseThreadInitThunk+0x14 (synthetic)
    2. Processor reads: SSP -> DraugrCall+offset (actual)
    3. Comparison: 0x14 ≠ DraugrCall+offset
    4. Exception: #CP (Control Protection Fault)
    5. Process Terminated
```

The shadow stack is hardware-protected with supervisor-only access rights, making it impossible for user-mode code to modify. Since Draugr relies on writing fabricated return addresses that differ from the actual call chain, CET detects the violation on the first RET instruction after stack manipulation. This represents a complete architectural mitigation with no user-mode bypass possible.


# Compilation

The project targets MinGW (GCC 13). Kali’s default MinGW is GCC 14, which triggers build errors. Use the provided Dockerfile to compile with MinGW-GCC 13.

```
sudo apt install docker.io
docker build -t ubuntu-gcc-13:latest .
docker run --rm -it -v "$PWD":/work -w /work ubuntu-gcc-13:latest make
```

# Credit

- https://www.unknowncheats.me/forum/anti-cheat-bypass/268039-x64-return-address-spoofing-source-explanation.html
- https://github.com/susMdT/LoudSunRun
- https://github.com/WithSecureLabs/CallStackSpoofer
- https://github.com/am0nsec/HellsGate
- https://blog.sektor7.net/#!res/2021/halosgate.md
- https://learn.microsoft.com/en-en/cpp/build/reference/cetcompat?view=msvc-170

For the kernel; same for userland
- https://learn.microsoft.com/en-en/windows-server/security/kernel-mode-hardware-stack-protection
- https://www.synacktiv.com/sites/default/files/2025-06/sstic_windows_kernel_shadow_stack_mitigation.pdf
