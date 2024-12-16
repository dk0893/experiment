import os, sys
from pwn import *

def prologue_python( prog, ss ):
    
    # level4.py起動
    proc = process( ['python', prog] )
    
    # "Please enter correct password for flag: "
    print( proc.recv(timeout=1) )
    
    print( ss )
    proc.sendline( ss )
    
    # "That password is incorrect"
    ret = proc.recvline()
    print( ret )
    
    return proc, ret

prog  = "level4.py"
pos_pw_list = ["158f", "1655", "d21e", "4966", "ed69", "1010", "dded", "844c", "40ab", "a948", "156c", "ab7f", "4a5f", "e38c", "ba12", "f7fd", "d780", "4f4d", "5ba1", "96c5", "55b9", "8a67", "d32b", "aa7a", "514b", "e4e1", "1230", "cd19", "d6dd", "b01f", "fd2f", "7587", "86c2", "d7b8", "55a2", "b77c", "7ffe", "4420", "e0ee", "d8fb", "d748", "b0fe", "2a37", "a638", "52db", "51b7", "5526", "40ed", "5356", "6ad4", "2ddd", "177d", "84ae", "cf88", "97a3", "17ad", "7124", "eff2", "e373", "c974", "7689", "b8b2", "e899", "d042", "47d9", "cca9", "ab2a", "de77", "4654", "9ecb", "ab6e", "bb8e", "b76b", "d661", "63f8", "7095", "567e", "b837", "2b80", "ad4f", "c514", "ffa4", "fc37", "7254", "b48b", "d38b", "a02b", "ec6c", "eacc", "8b70", "b03e", "1b36", "81ff", "77e4", "dbe6", "59d9", "fd6a", "5653", "8b95", "d0e5"]

for line in pos_pw_list:
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
