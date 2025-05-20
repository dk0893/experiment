#### PW Crack 5

次も Medium の問題です。4つのファイル（level5.py、level5.flag.txt.enc、level5.hash.bin、dictionary.txt）をダウンロードできます。

<figure class="figure-image figure-image-fotolife" title="PW Crack 5問題">[f:id:daisuke20240310:20241002221922p:plain:alt=PW Crack 5問題]<figcaption>PW Crack 5問題</figcaption></figure>

Pythonスクリプト（level5.py）は以下です。

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

実行すると、パスワードを聞かれるので、正しいパスワードを入力するとフラグが表示されそうです。

パスワードの辞書が提供されているので、それを 1つずつ入力すれば、いつかは正解しますが、辞書には、65536個のパスワードが含まれていました。

Pythonスクリプトを繰り返し実行する Pythonスクリプトを実装すれば良さそうです。pwntools を使います。

```python
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

実装して実行しましたが、かなり時間がかかります（2時間ぐらい）。逆順にやった方が絶対早いだろうなと思いましたが、やっぱり、だいぶ後ろの方でヒットしました。

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
（以下、省略）
```
