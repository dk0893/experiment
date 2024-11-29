BITS 64
global _start

_start:
	mov rax, 59
	jmp buf

setebx:
	pop rdi
	mov rsi, 0
	mov rdx, 0
	syscall

buf:
	call setebx
	db '/bin/sh', 0
