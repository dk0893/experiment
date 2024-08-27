.text
        .global _start
_start:
        mov     x0,  msg    // x0  "/bin/sh"
        adr     x1,  msg    // x1  string address
        mov     x2,  #0x0   // x2  NULL
        mov     x8,  #0xdd  // execve
        svc     #0
msg:
        .asciz  "/bin/sh"
