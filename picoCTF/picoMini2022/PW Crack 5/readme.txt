#### PW Crack 5

���� Medium �̖��ł��B4�̃t�@�C���ilevel5.py�Alevel5.flag.txt.enc�Alevel5.hash.bin�Adictionary.txt�j���_�E�����[�h�ł��܂��B

<figure class="figure-image figure-image-fotolife" title="PW Crack 5���">[f:id:daisuke20240310:20241002221922p:plain:alt=PW Crack 5���]<figcaption>PW Crack 5���</figcaption></figure>

Python�X�N���v�g�ilevel5.py�j�͈ȉ��ł��B

```python
import hashlib

### THIS FUNCTION WILL NOT HELP YOU FIND THE FLAG --LT ########################
def str_xor(secret, key):
    #extend key to secret length
    new_key = key
    i = 0
    while len(new_key) < len(secret):
        new_key = new_key + key[i]
        i = (i + 1) % len(key)        
    return "".join([chr(ord(secret_c) ^ ord(new_key_c)) for (secret_c,new_key_c) in zip(secret,new_key)])
###############################################################################

flag_enc = open('level5.flag.txt.enc', 'rb').read()
correct_pw_hash = open('level5.hash.bin', 'rb').read()

def hash_pw(pw_str):
    pw_bytes = bytearray()
    pw_bytes.extend(pw_str.encode())
    m = hashlib.md5()
    m.update(pw_bytes)
    return m.digest()

def level_5_pw_check():
    user_pw = input("Please enter correct password for flag: ")
    user_pw_hash = hash_pw(user_pw)
    
    if( user_pw_hash == correct_pw_hash ):
        print("Welcome back... your flag, user:")
        decryption = str_xor(flag_enc.decode(), user_pw)
        print(decryption)
        return
    print("That password is incorrect")

level_5_pw_check()
```

���s����ƁA�p�X���[�h�𕷂����̂ŁA�������p�X���[�h����͂���ƃt���O���\�����ꂻ���ł��B

�p�X���[�h�̎������񋟂���Ă���̂ŁA����� 1�����͂���΁A�����͐������܂����A�����ɂ́A65536�̃p�X���[�h���܂܂�Ă��܂����B

Python�X�N���v�g���J��Ԃ����s���� Python�X�N���v�g����������Ηǂ������ł��Bpwntools ���g���܂��B

```python
import os, sys
from pwn import *

def prologue_python( prog, ss ):
    
    # level5.py�N��
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
    for line in ff:
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
```

�������Ď��s���܂������A���Ȃ莞�Ԃ�������܂��i2���Ԃ��炢�j�B�t���ɂ����������Α������낤�ȂƎv���܂������A����ς�A�����Ԍ��̕��Ńq�b�g���܂����B

```sh
$ python tmp.py
line=0000

[+] Starting local process '/home/user/20240819/bin/python': pid 209134
b'Please enter correct password for flag: '
b'0000\n'
b'That password is incorrect\n'
[*] Stopped process '/home/user/20240819/bin/python' (pid 209134)
line=0001

[+] Starting local process '/home/user/20240819/bin/python': pid 209136
b'Please enter correct password for flag: '
b'0001\n'
b'That password is incorrect\n'
[*] Stopped process '/home/user/20240819/bin/python' (pid 209136)
line=0002
�i�ȉ��A�ȗ��j
```
