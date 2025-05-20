#### Shellcode

サーバとローカルファイルとがあります。普通に難しい pwn の問題っぽいです。

<figure class="figure-image figure-image-fotolife" title="PwnのShellcode問題">[f:id:daisuke20240310:20240918222118p:plain:alt=PwnのShellcode問題]<figcaption>PwnのShellcode問題</figcaption></figure>

解凍すると、shellcode というファイルが得られます。

まず、表層解析です。strip されてなくて、スタック実行が許可されてます。実行してみましたが、よく分かりません。変なファイル（Windowsプログラム）じゃなくて良かったです（笑）。

```sh
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
```

Ghidra で見てみます。main関数だけのようです。秘密の関数も特にありません。

```c
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
```

スタックバッファオーバーフローを、発生させて攻撃するのは間違いないですが、どうすればいいんでしょうか。あ、シェルコードを用意してくださいと書かれてますね。なるほどです。

[以前1](https://daisuke20240310.hatenablog.com/entry/shell2)、[以前2](https://daisuke20240310.hatenablog.com/entry/shell3) で、作ったシェルコードは ARM64用でした。今回は、x86-64 で作る必要があります。

以下の記事で、シェルコードを作りました。

[https://daisuke20240310.hatenablog.com/entry/chgbook2:embed:cite]

`flag{It_is_our_ch0ices_that_show_what_w3_truly_are_far_m0re_thAn_our_abi1ities}` でした。

