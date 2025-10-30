.code

Spoof proc

    pop    rax

    mov    r10, rdi
    mov    r11, rsi

    mov    rdi, [rsp + 32]
    mov    rsi, [rsp + 40]

    mov [rdi + 24], r10
    mov [rdi + 88], r11
    mov [rdi + 96], r12
    mov [rdi + 104], r13
    mov [rdi + 112], r14
    mov [rdi + 120], r15

    mov r12, rax

    xor r11, r11
    mov r13, [rsp + 30h]

    mov r14, 200h
    add r14, 8
    add r14, [rdi + 56]
    add r14, [rdi + 48]
    add r14, [rdi + 32]
    sub r14, 20h

    mov r10, rsp
    add r10, 30h

    looping:

        xor r15, r15
        cmp r11, r13
        je finish
        
        sub r14, 8
        mov r15, rsp
        sub r15, r14
        
        add r10, 8
        push [r10]
        pop [r15]

        add r11, 1
        jmp looping
    
    finish:

    sub    rsp, 200h

    push 0
    
    sub    rsp, [rdi + 56]
    mov    r11, [rdi + 64]
    mov    [rsp], r11
               
    sub    rsp, [rdi + 32]
    mov    r11, [rdi + 40]
    mov    [rsp], r11

    sub    rsp, [rdi + 48]
    mov    r11, [rdi + 80]
    mov    [rsp], r11

    mov    r11, rsi

    mov    [rdi + 8], r12
    mov    [rdi + 16], rbx
    lea    rbx, [fixup]
    mov    [rdi], rbx
    mov    rbx, rdi

    mov    r10, rcx
    mov    rax, [rdi + 72]
    
    jmp    r11

    fixup: 
  
        mov     rcx, rbx

        add     rsp, 200h
        add     rsp, [rbx + 48]
        add     rsp, [rbx + 32]
        add     rsp, [rbx + 56]

        mov     rbx, [rcx + 16]
        mov rdi, [rcx + 24]
        mov rsi, [rcx + 88]
        mov r12, [rcx + 96]
        mov r13, [rcx + 104]
        mov r14, [rcx + 112]
        mov r15, [rcx + 120]

        jmp     QWORD ptr [rcx + 8]

Spoof endp

end