#### PW Crack 4

���� Medium �̖��ł��B3�̃t�@�C���ilevel4.py�Alevel4.flag.txt.enc�Alevel4.hash.bin�j���_�E�����[�h�ł��܂��B

<figure class="figure-image figure-image-fotolife" title="PW Crack 4���">[f:id:daisuke20240310:20241003204050p:plain:alt=PW Crack 4���]<figcaption>PW Crack 4���</figcaption></figure>

��́uPW Crack 5�v�Ǝ��Ă��āA������ƊȒP�ł��B�O��Ɠ������A�p�X���[�h����͂��āA��������΁A�t���O���\������܂��B�O��́A�����t�@�C���� 65536�̃p�X���[�h�̌�₪�����Ă��܂������A������́A�_�E�����[�h�����ulevel4.py�v�̒��ɁA100�̃p�X���[�h��₪���X�g�ɒ�`����Ă����Ԃł��B

Python�X�N���v�g�ilevel4.py�j�͈ȉ��ł��B

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

flag_enc = open('level4.flag.txt.enc', 'rb').read()
correct_pw_hash = open('level4.hash.bin', 'rb').read()

def hash_pw(pw_str):
    pw_bytes = bytearray()
    pw_bytes.extend(pw_str.encode())
    m = hashlib.md5()
    m.update(pw_bytes)
    return m.digest()

def level_4_pw_check():
    user_pw = input("Please enter correct password for flag: ")
    user_pw_hash = hash_pw(user_pw)
    
    if( user_pw_hash == correct_pw_hash ):
        print("Welcome back... your flag, user:")
        decryption = str_xor(flag_enc.decode(), user_pw)
        print(decryption)
        return
    print("That password is incorrect")

level_4_pw_check()

# The strings below are 100 possibilities for the correct password. 
#   (Only 1 is correct)
pos_pw_list = ["158f", "1655", "d21e", "4966", "ed69", "1010", "dded", "844c", "40ab", "a948", "156c", "ab7f", "4a5f", "e38c", "ba12", "f7fd", "d780", "4f4d", "5ba1", "96c5", "55b9", "8a67", "d32b", "aa7a", "514b", "e4e1", "1230", "cd19", "d6dd", "b01f", "fd2f", "7587", "86c2", "d7b8", "55a2", "b77c", "7ffe", "4420", "e0ee", "d8fb", "d748", "b0fe", "2a37", "a638", "52db", "51b7", "5526", "40ed", "5356", "6ad4", "2ddd", "177d", "84ae", "cf88", "97a3", "17ad", "7124", "eff2", "e373", "c974", "7689", "b8b2", "e899", "d042", "47d9", "cca9", "ab2a", "de77", "4654", "9ecb", "ab6e", "bb8e", "b76b", "d661", "63f8", "7095", "567e", "b837", "2b80", "ad4f", "c514", "ffa4", "fc37", "7254", "b48b", "d38b", "a02b", "ec6c", "eacc", "8b70", "b03e", "1b36", "81ff", "77e4", "dbe6", "59d9", "fd6a", "5653", "8b95", "d0e5"]
```

��́uPW Crack 5�v�Ŏ������� Python�X�N���v�g�������ύX���܂��B

```python
import os, sys
from pwn import *

def prologue_python( prog, ss ):
    
    # level4.py�N��
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
```

���s���܂��B���x�� 1�����炢�Ńq�b�g���܂����B

```sh
$ python tmp.py
line=158f
[+] Starting local process '/home/user/20240819/bin/python': pid 209456
b'Please enter correct password for flag: '
b'158f'
b'That password is incorrect\n'
[*] Stopped process '/home/user/20240819/bin/python' (pid 209456)
line=1655
[+] Starting local process '/home/user/20240819/bin/python': pid 209458
b'Please enter correct password for flag: '
b'1655'
b'That password is incorrect\n'
[*] Stopped process '/home/user/20240819/bin/python' (pid 209458)
line=d21e
[+] Starting local process '/home/user/20240819/bin/python': pid 209460
b'Please enter correct password for flag: '
b'd21e'
b'That password is incorrect\n'
[*] Stopped process '/home/user/20240819/bin/python' (pid 209460)
�i�ȉ��A�ȗ��j
```
