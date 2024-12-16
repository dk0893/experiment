import os, sys
from pwn import *

def prologue_python( prog, ss ):
    
    # level5.py起動
    proc = process( ['python', prog] )
    
    # "Please enter correct password for flag: "
    print( proc.recv(timeout=1) )
    
    print( ss )
    proc.sendline( ss )
    
    # "That password is incorrect"
    ret = proc.recvline()
    print( ret )
    
    return proc, ret

fpath = "dictionary.txt"
prog  = "level5.py"

with open(fpath) as ff:
    lines = ff.readlines()
    for line in reversed(lines):
        print( f"line={line}" )
        proc, ret = prologue_python( prog, line.encode('utf-8') )
        if "Welcome" in ret.decode('utf-8'):
            break
        else:
            proc.close()

print( proc.recvline() )
print( proc.recvline() )
print( proc.recvline() )
print( proc.recvline() )
