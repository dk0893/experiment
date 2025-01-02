Medium の問題です。

更新されたバイナリファイル（crackme100）が 1つダウンロードできます。

また、最後はサーバを起動して実行する必要があるようです。

表層解析を行います。stringsコマンドでフラグが見えてますが、ローカルファイル用のフラグということでしょうか。

```sh
$ file crackme100 
crackme100: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=f680c44f890f619e9d88949f9048709d008b18f1, for GNU/Linux 3.2.0, with debug_info, not stripped

$ checksec --file=crackme100
RELRO          STACK CANARY     NX          PIE     RPATH     RUNPATH     Symbols     FORTIFY  Fortified  Fortifiable  FILE
Partial RELRO  No canary found  NX enabled  No PIE  No RPATH  No RUNPATH  40 Symbols  No       0          1            crackme100

$ strings crackme100 | grep pico
picoCTF{sample_flag}
```

まず、実行してみます。正しいパスワードを入力する必要がありそうです。

```sh
$ ./crackme100
Enter the secret password: aaa
FAILED!
```

Ghidra を使って、ソースを見ていきます。なんか正統派な問題って感じです。

二重ループのところを読み解いてみます。外側は 3回、内側は 配列変数の output の文字数なので 50回実行されそうです。

検討が長くなりそうなので、ソースコードの下に書いていきます。

```c
int main(void)
{
  uint uVar1;
  int iVar2;
  size_t sVar3;
  char input [51];
  char output [51];
  int random2;
  int random1;
  char fix;
  int secret3;
  int secret2;
  int secret1;
  int len;
  int i_1;
  int i;
  
  output[0] = 'k';
  output[1] = 'g';
  output[2] = 'x';
  output[3] = 'm';
  output[4] = 'w';
  output[5] = 'p';
  output[6] = 'b';
  output[7] = 'p';
  output[8] = 'u';
  output[9] = 'q';
  output[10] = 't';
  output[0xb] = 'o';
  output[0xc] = 'r';
  output[0xd] = 'z';
  output[0xe] = 'a';
  output[0xf] = 'p';
  output[0x10] = 'j';
  output[0x11] = 'h';
  output[0x12] = 'f';
  output[0x13] = 'm';
  output[0x14] = 'e';
  output[0x15] = 'b';
  output[0x16] = 'm';
  output[0x17] = 'c';
  output[0x18] = 'c';
  output[0x19] = 'v';
  output[0x1a] = 'w';
  output[0x1b] = 'y';
  output[0x1c] = 'c';
  output[0x1d] = 'y';
  output[0x1e] = 'v';
  output[0x1f] = 'e';
  output[0x20] = 'w';
  output[0x21] = 'p';
  output[0x22] = 'x';
  output[0x23] = 'i';
  output[0x24] = 'h';
  output[0x25] = 'e';
  output[0x26] = 'i';
  output[0x27] = 'f';
  output[0x28] = 'v';
  output[0x29] = 'n';
  output[0x2a] = 'u';
  output[0x2b] = 'q';
  output[0x2c] = 's';
  output[0x2d] = 'r';
  output[0x2e] = 'g';
  output[0x2f] = 'e';
  output[0x30] = 'x';
  output[0x31] = 'l';
  output[0x32] = '\0';
  setvbuf(stdout,(char *)0x0,2,0);
  printf("Enter the secret password: ");
  __isoc99_scanf(&DAT_00402024,input);
  i = 0;
  sVar3 = strlen(output);
  for (; i < 3; i = i + 1) {
    for (i_1 = 0; i_1 < (int)sVar3; i_1 = i_1 + 1) {
      uVar1 = (i_1 % 0xff >> 1 & 0x55U) + (i_1 % 0xff & 0x55U);
      uVar1 = ((int)uVar1 >> 2 & 0x33U) + (uVar1 & 0x33);
      iVar2 = ((int)uVar1 >> 4) + input[i_1] + -0x61 + (uVar1 & 0xf);
      input[i_1] = (char)iVar2 + (char)(iVar2 / 0x1a) * -0x1a + 'a';
    }
  }
  iVar2 = memcmp(input,output,(long)(int)sVar3);
  if (iVar2 == 0) {
    printf("SUCCESS! Here is your flag: %s\n","picoCTF{sample_flag}");
  }
  else {
    puts("FAILED!");
  }
  return 0;
}
```

ループの内側の 4行を詳しく見ます。

1行目は、演算子の優先順位を正しく見る必要があるので括弧を付けます。また、`i_1` は 0 から 49 をとるので、`% 0xff` は無視できます。

`uVar1 = (((i_1 % 0xff) >> 1) & 0x55U) + ((i_1 % 0xff) & 0x55U);`

よって、以下のように簡単にできます。

`uVar1 = ((i_1 >> 1) & 0x55U) + (i_1 & 0x55U);`

うーん、このやり方は無謀でした。やめます。

4行のうち、input 以外は値が決まっていることと、i は 4行に出てこないこと、ある input の計算に、他の input が関係しないことが分かります。

つまり、ある input の場合に、この 4行を 3回連続でやった結果と同じです。

プログラムで ASCIIコードを総当たりで計算するのがいいかもしれません。英小文字だけでいけそうですし。

Pythonスクリプトを実装します。

C言語から、Python に変換するだけでした。

これを実行すると、正しいパスワードが表示されます。

サーバで同じパスワードを入力すると、フラグが表示されました。

```python
import os, sys

output = "kgxmwpbpuqtorzapjhfmebmccvwycyvewpxiheifvnuqsrgexl"

ret = []
for i_1, out in enumerate(output):
    
    tmps = [ aa for aa in range(0x21, 0x7f) ]
    #print( tmps )
    
    flag = False
    for tmp in tmps:
        input = tmp
        for ii in range(3):
            
            uVar1 = ((((i_1 % 0xff) >> 1)) & 0x55) + ((i_1 % 0xff) & 0x55)
            uVar1 = ((uVar1 >> 2) & 0x33) + (uVar1 & 0x33)
            iVar2 = (uVar1 >> 4) + input - 0x61 + (uVar1 & 0xf)
            input = (iVar2 & 0xff) - ((iVar2 // 0x1a) & 0xff) * (0x1a) + 0x61
        
        #print( f"out={out}, ord(out)={ord(out)}" )
        
        if input == ord( out ):
            ret.append( chr(tmp) )
            flag = True
            break
    
    assert flag, f"fail, ret={ret}"

print( f"ret={''.join(ret)}" )
```


やってみます。

```sh
$ python crackme100.py
ret=kdugtjvgrknflqrdgb`d_sdqwmnmtmjptjr`bv`tpelejfuprc

$ ./crackme100
Enter the secret password: kdugtjvgrknflqrdgb`d_sdqwmnmtmjptjr`bv`tpelejfuprc
SUCCESS! Here is your flag: picoCTF{sample_flag}
```

サーバに対して実施するとフラグが表示されます。

