1�� Python�X�N���v�g�itoken_generator.py�j���_�E�����[�h�ł��܂��B���ƁA�T�[�o���N�����Đi�߂�悤�ł��B

<figure class="figure-image figure-image-fotolife" title="Chronohack�i200 points�j">[f:id:daisuke20240310:20250310225721p:plain:alt=Chronohack�i200 points�j]<figcaption>Chronohack�i200 points�j</figcaption></figure>

Python�X�N���v�g�͈ȉ��ł��B

�܂��A20�����̕�������擾���āA�g�[�N���Ƃ��܂��B���[�U������͂𓾂āA�g�[�N���ƈ�v������t���O���\�������悤�ł��B���ʂɍl�����疳���ł��ˁB

```python
import random
import time

def get_random(length):
    alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    random.seed(int(time.time() * 1000))  # seeding with current time 
    s = ""
    for i in range(length):
        s += random.choice(alphabet)
    return s

def flag():
    with open('/flag.txt', 'r') as picoCTF:
        content = picoCTF.read()
        print(content)


def main():
    print("Welcome to the token generation challenge!")
    print("Can you guess the token?")
    token_length = 20  # the token length
    token = get_random(token_length) 

    try:
        n=0
        while n < 50:
            user_guess = input("\nEnter your guess for the token (or exit):").strip()
            n+=1
            if user_guess == "exit":
                print("Exiting the program...")
                break
            
            if user_guess == token:
                print("Congratulations! You found the correct token.")
                flag()
                break
            else:
                print("Sorry, your token does not match. Try again!")
            if n == 50:
                print("\nYou exhausted your attempts, Bye!")
    except KeyboardInterrupt:
        print("\nKeyboard interrupt detected. Exiting the program...")

if __name__ == "__main__":
    main()
```

�����V�[�h���A`time.time()` �Ȃ̂ŁA���ݎ����̂悤�ł��B����͗\���ł���Ƃ������Ƃł��傤���B���������V�[�h�ŁA50��̃`�������W���o����̂ŁA�Ȃ�Ƃ��Ȃ肻���ł��B

Python �� pwntools ���g���Ď������܂����B

```python
import random
import time
from pwn import *

def get_random(length, seed):
    alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    random.seed(seed)  # seeding with current time 
    s = ""
    for i in range(length):
        s += random.choice(alphabet)
    return s

def main(delay):
    
    adrs = "verbal-sleep.picoctf.net"
    port = 57465
    #adrs = "localhost"
    #port = 4000
    
    proc = remote( adrs, port )
    
    now = time.time()
    
    try:
        n = 0
        while n < 50:
            
            ret = proc.recvuntil( ':' )
            
            seed = int((now) * 1000) + n + delay
            #seed = int((now) * 1000)
            
            info( f"recv ret={ret}', seed={seed}" )
            
            ss = get_random( 20, seed )
            
            proc.sendline( ss.encode("utf-8") )
            ret = proc.recvline()
            info( f"send ss={ss}, recv ret={ret}" )
            if 'Congratulations' in ret.decode("utf-8"):
                info( proc.recvline() )
                info( proc.recvline() )
                info( proc.recvline() )
                info( proc.recvline() )
            
            n += 1
    
    except KeyboardInterrupt:
        print("\nKeyboard interrupt detected. Exiting the program...")
    except EOFError:
        print( f"********* ret={ret} *********" )

if __name__ == "__main__":
    for ii in range(1000):
        main( ii * 30 )
```

�ȉ��́A���������Ƃ���ł��B���Ȃ��J���āA�Ȃ�Ƃ����Ă邱�Ƃ��o���܂����B���͉��x�����ĂĂ��̂ł����A�W���o�͂Ƀt���O��\���ł��ĂȂ�������ȂǁA�܂� pwntools ���g�����Ȃ��ĂȂ������ł����B

```sh
$ python token_generator_pwntools.py > 20250311_2.log 2>&1 &

$ tail -f 20250311_2.log
�i�r���ȗ��j
[*] recv ret=b'\nEnter your guess for the token (or exit):'', seed=1741701063299
[*] send ss=QvkOjQzT1o4vdLkOBOcL, recv ret=b'Sorry, your token does not match. Try again!\n'
[*] recv ret=b'\nEnter your guess for the token (or exit):'', seed=1741701063300
[*] send ss=4MDrmzpg2YJWNCisQgN0, recv ret=b'Sorry, your token does not match. Try again!\n'
[*] recv ret=b'\nEnter your guess for the token (or exit):'', seed=1741701063301
[*] send ss=x9QriVKHlbbIBJ9TMm9t, recv ret=b'Sorry, your token does not match. Try again!\n'
[*] recv ret=b'\nEnter your guess for the token (or exit):'', seed=1741701063302
[*] send ss=wTECACj6qoJqnmLulH8N, recv ret=b'Sorry, your token does not match. Try again!\n'
[*] recv ret=b'\nEnter your guess for the token (or exit):'', seed=1741701063303
[*] send ss=j5xEiw8db900Toy3EjC1, recv ret=b'Sorry, your token does not match. Try again!\n'
[*] recv ret=b'\nEnter your guess for the token (or exit):'', seed=1741701063304
[*] send ss=jt4XtryCEHxhxzohjbCO, recv ret=b'Sorry, your token does not match. Try again!\n'
[*] recv ret=b'\nEnter your guess for the token (or exit):'', seed=1741701063305
[*] send ss=vq1qnqESQihBi9L8eEmN, recv ret=b'Sorry, your token does not match. Try again!\n'
[*] recv ret=b'\nEnter your guess for the token (or exit):'', seed=1741701063306
[*] send ss=bfQDEvV8nbbxmVEp21Oa, recv ret=b'Sorry, your token does not match. Try again!\n'
[*] recv ret=b'\nEnter your guess for the token (or exit):'', seed=1741701063307
[*] send ss=6T40hEAGtddkQ7bSjXzF, recv ret=b'Sorry, your token does not match. Try again!\n'
[*] recv ret=b'\nEnter your guess for the token (or exit):'', seed=1741701063308
[*] send ss=K7gBgnZpJipAOCQoG4FO, recv ret=b'Sorry, your token does not match. Try again!\n'
[*] recv ret=b'\nEnter your guess for the token (or exit):'', seed=1741701063309
[*] send ss=MgdeQQt5UnxZPIVv8bWZ, recv ret=b'Sorry, your token does not match. Try again!\n'
[*] recv ret=b'\nEnter your guess for the token (or exit):'', seed=1741701063310
[*] send ss=XzZcLl3W5OCtbmaeAnfx, recv ret=b'Congratulations! You found the correct token.\n'
/home/user/20240819/lib/python3.11/site-packages/pwnlib/log.py:396: BytesWarning: Bytes is not text; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  self._log(logging.INFO, message, args, kwargs, 'info')
[*] picoCTF{UseSecure#$_Random@j3n3r@T0rsde389b79}
********* ret=b'Congratulations! You found the correct token.\n' *********
[x] Opening connection to verbal-sleep.picoctf.net on port 64908
[x] Opening connection to verbal-sleep.picoctf.net on port 64908: Trying 3.138.217.147
[+] Opening connection to verbal-sleep.picoctf.net on port 64908: Done
[*] recv ret=b'Welcome to the token generation challenge!\nCan you guess the token?\n\nEnter your guess for the token (or exit):'', seed=1741701074622
[*] send ss=iRxlltvft4QWUWdw11IL, recv ret=b'Sorry, your token does not match. Try again!\n'
[*] recv ret=b'\nEnter your guess for the token (or exit):'', seed=1741701074623
[*] send ss=FMiKR1WRoC6zEh7XkDu0, recv ret=b'Sorry, your token does not match. Try again!\n'
```
