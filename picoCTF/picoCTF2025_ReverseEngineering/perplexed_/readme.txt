1つの実行ファイル（perplexed）がダウンロードできます。問題文には何も書かれていません。

<figure class="figure-image figure-image-fotolife" title="perplexed（400 points）">[f:id:daisuke20240310:20250313215513p:plain:alt=perplexed（400 points）]<figcaption>perplexed（400 points）</figcaption></figure>

とりあえず、表層解析します。

```sh
$ file perplexed
perplexed: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=85480b12e666f376909d57d282a1ef0f30e93db4, for GNU/Linux 3.2.0, not stripped

$ ~/bin/checksec --file=perplexed
RELRO          STACK CANARY     NX          PIE     RPATH     RUNPATH     Symbols     FORTIFY  Fortified  Fortifiable  FILE
Partial RELRO  No canary found  NX enabled  No PIE  No RPATH  No RUNPATH  39 Symbols  No       0          2            perplexed

$ pwn checksec --file=perplexed
[*] '/home/user/svn/experiment/picoCTF/picoCTF2025_ReverseEngineering/perplexed'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    Stripped:   No
```

実行してみます。パスワードを入力させるプログラムのようです。

```sh
$ ./perplexed
Enter the password: xxxxxxxx
Wrong :(
```

Ghidra で見ていきます。

main関数は、ユーザにパスワードを入力させて、check関数を実行して、その戻り値が 1以外なら成功ということのようです。

```c
bool main(void)
{
  bool bVar1;
  undefined8 local_118;
  undefined8 local_110;
  undefined8 local_108;
  undefined8 local_100;
  undefined8 local_f8;
  undefined8 local_f0;
  undefined8 local_e8;
  undefined8 local_e0;
  undefined8 local_d8;
  undefined8 local_d0;
  undefined8 local_c8;
  undefined8 local_c0;
  undefined8 local_b8;
  undefined8 local_b0;
  undefined8 local_a8;
  undefined8 local_a0;
  undefined8 local_98;
  undefined8 local_90;
  undefined8 local_88;
  undefined8 local_80;
  undefined8 local_78;
  undefined8 local_70;
  undefined8 local_68;
  undefined8 local_60;
  undefined8 local_58;
  undefined8 local_50;
  undefined8 local_48;
  undefined8 local_40;
  undefined8 local_38;
  undefined8 local_30;
  undefined8 local_28;
  undefined8 local_20;
  int local_c;
  
  local_118 = 0;
  local_110 = 0;
  local_108 = 0;
  local_100 = 0;
  local_f8 = 0;
  local_f0 = 0;
  local_e8 = 0;
  local_e0 = 0;
  local_d8 = 0;
  local_d0 = 0;
  local_c8 = 0;
  local_c0 = 0;
  local_b8 = 0;
  local_b0 = 0;
  local_a8 = 0;
  local_a0 = 0;
  local_98 = 0;
  local_90 = 0;
  local_88 = 0;
  local_80 = 0;
  local_78 = 0;
  local_70 = 0;
  local_68 = 0;
  local_60 = 0;
  local_58 = 0;
  local_50 = 0;
  local_48 = 0;
  local_40 = 0;
  local_38 = 0;
  local_30 = 0;
  local_28 = 0;
  local_20 = 0;
  printf("Enter the password: ");
  fgets((char *)&local_118,0x100,stdin);
  local_c = check(&local_118);
  bVar1 = local_c != 1;
  if (bVar1) {
    puts("Correct!! :D");
  }
  else {
    puts("Wrong :(");
  }
  return !bVar1;
}
```

次は、check関数を見てみます。パスワード長は 27文字でなければなりません。実際は改行が含まれるようなので、26文字でした。

ちょっと分かりにくいですが、スタックの rbp - 0x50 から、23byte のデータがあります。ざっくり言うと、この 23byte のデータと、パスワードのデータをビット単位で比較して、XOR して、0 になるビットであれば、それが正しいパスワードということになります。ただし、23byte のデータで使うビット位置とパスワードのビット位置は異なる動きをするようなので、そこの見極めが難しそうです。

```c
undefined8 check(char *param_1)
{
  size_t sVar1;
  undefined8 uVar2;
  size_t sVar3;
  undefined8 local_58;
  undefined7 local_50;
  undefined uStack_49;
  undefined7 uStack_48;
  uint local_34;
  uint local_30;
  undefined4 local_2c;
  int local_28;
  uint local_24;
  int local_20;
  int local_1c;
  
  sVar1 = strlen(param_1);
  if (sVar1 == 0x1b) {
    local_58 = 0x617b2375f81ea7e1;
    local_50 = 0x69df5b5afc9db9;
    uStack_49 = 0xd2;
    uStack_48 = 0xf467edf4ed1bfe;
    local_1c = 0;
    local_20 = 0;
    local_2c = 0;
    for (local_24 = 0; local_24 < 0x17; local_24 = local_24 + 1) {
      for (local_28 = 0; local_28 < 8; local_28 = local_28 + 1) {
        if (local_20 == 0) {
          local_20 = 1;
        }
        local_30 = 1 << (7U - (char)local_28 & 0x1f);
        local_34 = 1 << (7U - (char)local_20 & 0x1f);
        if (0 < (int)((int)param_1[local_1c] & local_34) !=
            0 < (int)((int)*(char *)((long)&local_58 + (long)(int)local_24) & local_30)) {
          return 1;
        }
        local_20 = local_20 + 1;
        if (local_20 == 8) {
          local_20 = 0;
          local_1c = local_1c + 1;
        }
        sVar3 = (size_t)local_1c;
        sVar1 = strlen(param_1);
        if (sVar3 == sVar1) {
          return 0;
        }
      }
    }
    uVar2 = 0;
  }
  else {
    uVar2 = 1;
  }
  return uVar2;
}

```

スタックを可視化します。

| アドレス | サイズ | 内容 |
| - | - | - |
| rbp |
| rbp - 0x14 | 4 | local_1c |
| rbp - 0x18 | 4 | local_20（1→2→...→7→1→...） |
| rbp - 0x1C | 4 | local_24 |
| rbp - 0x20 | 4 | local_28 |
| rbp - 0x24 | 4 | 空き |
| rbp - 0x28 | 4 | local_30（0x80→0x40→...→0x00→0x80→...） |
| rbp - 0x2C | 4 | local_34（0x40→0x20→...→0x00→0x40→...） |
| rbp - 0x40 | 8 | fe, 1b, ed, f4, ed, 67, f4, 00（0x00f467edf4ed1bfe） |
| rbp - 0x48 | 8 | b9, 9d, fc, 5a, 5b, df, 69, d2（0xd269df5b5afc9db9） |
| rbp - 0x50 | 8 | e1, a7, 1e, f8, 75, 23, 7b, 61（0x617b2375f81ea7e1） |
| rbp - 0x58 | 8 | passwordのアドレス |

GDB で表示したアセンブラも貼っておきます。

```sh
pwndbg> disassemble 
Dump of assembler code for function check:
   0x0000000000401156 <+0>:	push   rbp
   0x0000000000401157 <+1>:	mov    rbp,rsp
   0x000000000040115a <+4>:	push   rbx
   0x000000000040115b <+5>:	sub    rsp,0x58
   0x000000000040115f <+9>:	mov    QWORD PTR [rbp-0x58],rdi
   0x0000000000401163 <+13>:	mov    rax,QWORD PTR [rbp-0x58]
   0x0000000000401167 <+17>:	mov    rdi,rax
   0x000000000040116a <+20>:	call   0x401040 <strlen@plt>
   0x000000000040116f <+25>:	cmp    rax,0x1b
   0x0000000000401173 <+29>:	je     0x40117f <check+41>
   0x0000000000401175 <+31>:	mov    eax,0x1
   0x000000000040117a <+36>:	jmp    0x40129f <check+329>
   0x000000000040117f <+41>:	movabs rax,0x617b2375f81ea7e1
   0x0000000000401189 <+51>:	movabs rdx,0xd269df5b5afc9db9
   0x0000000000401193 <+61>:	mov    QWORD PTR [rbp-0x50],rax
   0x0000000000401197 <+65>:	mov    QWORD PTR [rbp-0x48],rdx
   0x000000000040119b <+69>:	movabs rax,0xf467edf4ed1bfed2
   0x00000000004011a5 <+79>:	mov    QWORD PTR [rbp-0x41],rax
   0x00000000004011a9 <+83>:	mov    DWORD PTR [rbp-0x14],0x0
   0x00000000004011b0 <+90>:	mov    DWORD PTR [rbp-0x18],0x0
   0x00000000004011b7 <+97>:	mov    DWORD PTR [rbp-0x24],0x0
   0x00000000004011be <+104>:	mov    DWORD PTR [rbp-0x1c],0x0
   0x00000000004011c5 <+111>:	jmp    0x40128e <check+312>
   0x00000000004011ca <+116>:	mov    DWORD PTR [rbp-0x20],0x0
   0x00000000004011d1 <+123>:	jmp    0x401280 <check+298>
   0x00000000004011d6 <+128>:	cmp    DWORD PTR [rbp-0x18],0x0
   0x00000000004011da <+132>:	jne    0x4011e0 <check+138>
   0x00000000004011dc <+134>:	add    DWORD PTR [rbp-0x18],0x1
   0x00000000004011e0 <+138>:	mov    eax,0x7
   0x00000000004011e5 <+143>:	sub    eax,DWORD PTR [rbp-0x20]
   0x00000000004011e8 <+146>:	mov    edx,0x1
   0x00000000004011ed <+151>:	mov    ecx,eax
   0x00000000004011ef <+153>:	shl    edx,cl
   0x00000000004011f1 <+155>:	mov    eax,edx
   0x00000000004011f3 <+157>:	mov    DWORD PTR [rbp-0x28],eax
   0x00000000004011f6 <+160>:	mov    eax,0x7
   0x00000000004011fb <+165>:	sub    eax,DWORD PTR [rbp-0x18]
   0x00000000004011fe <+168>:	mov    edx,0x1
   0x0000000000401203 <+173>:	mov    ecx,eax
   0x0000000000401205 <+175>:	shl    edx,cl
   0x0000000000401207 <+177>:	mov    eax,edx
   0x0000000000401209 <+179>:	mov    DWORD PTR [rbp-0x2c],eax
   0x000000000040120c <+182>:	mov    eax,DWORD PTR [rbp-0x1c]
   0x000000000040120f <+185>:	cdqe
   0x0000000000401211 <+187>:	movzx  eax,BYTE PTR [rbp+rax*1-0x50]
   0x0000000000401216 <+192>:	movsx  eax,al
   0x0000000000401219 <+195>:	and    eax,DWORD PTR [rbp-0x28]
   0x000000000040121c <+198>:	test   eax,eax
   0x000000000040121e <+200>:	setg   cl
   0x0000000000401221 <+203>:	mov    eax,DWORD PTR [rbp-0x14]
   0x0000000000401224 <+206>:	movsxd rdx,eax
   0x0000000000401227 <+209>:	mov    rax,QWORD PTR [rbp-0x58]
   0x000000000040122b <+213>:	add    rax,rdx
   0x000000000040122e <+216>:	movzx  eax,BYTE PTR [rax]
   0x0000000000401231 <+219>:	movsx  eax,al
   0x0000000000401234 <+222>:	and    eax,DWORD PTR [rbp-0x2c]
   0x0000000000401237 <+225>:	test   eax,eax
   0x0000000000401239 <+227>:	setg   al
   0x000000000040123c <+230>:	xor    eax,ecx
   0x000000000040123e <+232>:	test   al,al
=> 0x0000000000401240 <+234>:	je     0x401249 <check+243>
   0x0000000000401242 <+236>:	mov    eax,0x1
   0x0000000000401247 <+241>:	jmp    0x40129f <check+329>
   0x0000000000401249 <+243>:	add    DWORD PTR [rbp-0x18],0x1
   0x000000000040124d <+247>:	cmp    DWORD PTR [rbp-0x18],0x8
   0x0000000000401251 <+251>:	jne    0x40125e <check+264>
   0x0000000000401253 <+253>:	mov    DWORD PTR [rbp-0x18],0x0
   0x000000000040125a <+260>:	add    DWORD PTR [rbp-0x14],0x1
   0x000000000040125e <+264>:	mov    eax,DWORD PTR [rbp-0x14]
   0x0000000000401261 <+267>:	movsxd rbx,eax
   0x0000000000401264 <+270>:	mov    rax,QWORD PTR [rbp-0x58]
   0x0000000000401268 <+274>:	mov    rdi,rax
   0x000000000040126b <+277>:	call   0x401040 <strlen@plt>
   0x0000000000401270 <+282>:	cmp    rbx,rax
   0x0000000000401273 <+285>:	jne    0x40127c <check+294>
   0x0000000000401275 <+287>:	mov    eax,0x0
   0x000000000040127a <+292>:	jmp    0x40129f <check+329>
   0x000000000040127c <+294>:	add    DWORD PTR [rbp-0x20],0x1
   0x0000000000401280 <+298>:	cmp    DWORD PTR [rbp-0x20],0x7
   0x0000000000401284 <+302>:	jle    0x4011d6 <check+128>
   0x000000000040128a <+308>:	add    DWORD PTR [rbp-0x1c],0x1
   0x000000000040128e <+312>:	mov    eax,DWORD PTR [rbp-0x1c]
   0x0000000000401291 <+315>:	cmp    eax,0x16
   0x0000000000401294 <+318>:	jbe    0x4011ca <check+116>
   0x000000000040129a <+324>:	mov    eax,0x0
   0x000000000040129f <+329>:	mov    rbx,QWORD PTR [rbp-0x8]
   0x00000000004012a3 <+333>:	leave
   0x00000000004012a4 <+334>:	ret
End of assembler dump.
```

同じ動きをする Pythonスクリプトを作ります。条件を満たすビットを論理和で重ねていけば、求められているパスワードが作られていく、みたいな感じにしてみます。

```python
def main():
    
    password = "abcdefghijklmnopqrstuvwxyz"
    
    lst = [ 0xe1, 0xa7, 0x1e, 0xf8, 0x75, 0x23, 0x7b, 0x61, 0xb9, 0x9d, 0xfc, 0x5a, 0x5b, 0xdf, 0x69, 0xd2, 0xfe, 0x1b, 0xed, 0xf4, 0xed, 0x67, 0xf4, 0x00, 0x00, 0x00, 0x00, 0x00 ]
    ret = [ 0 ] * 27
    
    l_1c = 0
    l_20 = 0
    for l_24 in range( 23 ):
        for l_28 in range( 8 ):
            
            if l_20 == 0:
                l_20 = 1
            
            l_30 = 1 << ( (7 - l_28) & 0x1F )
            l_34 = 1 << ( (7 - l_20) & 0x1F )
            
            #if (0 < ord(password[l_1c]) & l_34) != (0 < (lst[l_24] & l_30)):
            #    print( "failure" )
            
            if (lst[l_24] & l_30) != 0:
                ret[l_1c] |= l_34
            
            print( f"ii={l_24:2d}, jj={l_28}: l_30=0x{l_30:02X}, l_34=0x{l_34:02X}, l_20={l_20}, l_1c={l_1c}" )
            
            l_20 += 1
            if l_20 == 8:
                l_20 = 0
                l_1c += 1
            
            if l_1c == 27:
                print( "success" )
    
    ret = [ chr(ii) for ii in ret ]
    ret = "".join( ret )
    print( ret )

if __name__ == "__main__":
    main()
```

実行してみます。出ました！

```sh
$ python perplexed.py
ii= 0, jj=0: l_30=0x80, l_34=0x40, l_20=1, l_1c=0
ii= 0, jj=1: l_30=0x40, l_34=0x20, l_20=2, l_1c=0
ii= 0, jj=2: l_30=0x20, l_34=0x10, l_20=3, l_1c=0
ii= 0, jj=3: l_30=0x10, l_34=0x08, l_20=4, l_1c=0
ii= 0, jj=4: l_30=0x08, l_34=0x04, l_20=5, l_1c=0
ii= 0, jj=5: l_30=0x04, l_34=0x02, l_20=6, l_1c=0
ii= 0, jj=6: l_30=0x02, l_34=0x01, l_20=7, l_1c=0
ii= 0, jj=7: l_30=0x01, l_34=0x40, l_20=1, l_1c=1
ii= 1, jj=0: l_30=0x80, l_34=0x20, l_20=2, l_1c=1
ii= 1, jj=1: l_30=0x40, l_34=0x10, l_20=3, l_1c=1
ii= 1, jj=2: l_30=0x20, l_34=0x08, l_20=4, l_1c=1
ii= 1, jj=3: l_30=0x10, l_34=0x04, l_20=5, l_1c=1
ii= 1, jj=4: l_30=0x08, l_34=0x02, l_20=6, l_1c=1
ii= 1, jj=5: l_30=0x04, l_34=0x01, l_20=7, l_1c=1
ii= 1, jj=6: l_30=0x02, l_34=0x40, l_20=1, l_1c=2
ii= 1, jj=7: l_30=0x01, l_34=0x20, l_20=2, l_1c=2
ii= 2, jj=0: l_30=0x80, l_34=0x10, l_20=3, l_1c=2
ii= 2, jj=1: l_30=0x40, l_34=0x08, l_20=4, l_1c=2
ii= 2, jj=2: l_30=0x20, l_34=0x04, l_20=5, l_1c=2
ii= 2, jj=3: l_30=0x10, l_34=0x02, l_20=6, l_1c=2
ii= 2, jj=4: l_30=0x08, l_34=0x01, l_20=7, l_1c=2
ii= 2, jj=5: l_30=0x04, l_34=0x40, l_20=1, l_1c=3
ii= 2, jj=6: l_30=0x02, l_34=0x20, l_20=2, l_1c=3
ii= 2, jj=7: l_30=0x01, l_34=0x10, l_20=3, l_1c=3
ii= 3, jj=0: l_30=0x80, l_34=0x08, l_20=4, l_1c=3
ii= 3, jj=1: l_30=0x40, l_34=0x04, l_20=5, l_1c=3
ii= 3, jj=2: l_30=0x20, l_34=0x02, l_20=6, l_1c=3
ii= 3, jj=3: l_30=0x10, l_34=0x01, l_20=7, l_1c=3
ii= 3, jj=4: l_30=0x08, l_34=0x40, l_20=1, l_1c=4
ii= 3, jj=5: l_30=0x04, l_34=0x20, l_20=2, l_1c=4
ii= 3, jj=6: l_30=0x02, l_34=0x10, l_20=3, l_1c=4
ii= 3, jj=7: l_30=0x01, l_34=0x08, l_20=4, l_1c=4
ii= 4, jj=0: l_30=0x80, l_34=0x04, l_20=5, l_1c=4
ii= 4, jj=1: l_30=0x40, l_34=0x02, l_20=6, l_1c=4
ii= 4, jj=2: l_30=0x20, l_34=0x01, l_20=7, l_1c=4
ii= 4, jj=3: l_30=0x10, l_34=0x40, l_20=1, l_1c=5
ii= 4, jj=4: l_30=0x08, l_34=0x20, l_20=2, l_1c=5
ii= 4, jj=5: l_30=0x04, l_34=0x10, l_20=3, l_1c=5
ii= 4, jj=6: l_30=0x02, l_34=0x08, l_20=4, l_1c=5
ii= 4, jj=7: l_30=0x01, l_34=0x04, l_20=5, l_1c=5
ii= 5, jj=0: l_30=0x80, l_34=0x02, l_20=6, l_1c=5
ii= 5, jj=1: l_30=0x40, l_34=0x01, l_20=7, l_1c=5
ii= 5, jj=2: l_30=0x20, l_34=0x40, l_20=1, l_1c=6
ii= 5, jj=3: l_30=0x10, l_34=0x20, l_20=2, l_1c=6
ii= 5, jj=4: l_30=0x08, l_34=0x10, l_20=3, l_1c=6
ii= 5, jj=5: l_30=0x04, l_34=0x08, l_20=4, l_1c=6
ii= 5, jj=6: l_30=0x02, l_34=0x04, l_20=5, l_1c=6
ii= 5, jj=7: l_30=0x01, l_34=0x02, l_20=6, l_1c=6
ii= 6, jj=0: l_30=0x80, l_34=0x01, l_20=7, l_1c=6
ii= 6, jj=1: l_30=0x40, l_34=0x40, l_20=1, l_1c=7
ii= 6, jj=2: l_30=0x20, l_34=0x20, l_20=2, l_1c=7
ii= 6, jj=3: l_30=0x10, l_34=0x10, l_20=3, l_1c=7
ii= 6, jj=4: l_30=0x08, l_34=0x08, l_20=4, l_1c=7
ii= 6, jj=5: l_30=0x04, l_34=0x04, l_20=5, l_1c=7
ii= 6, jj=6: l_30=0x02, l_34=0x02, l_20=6, l_1c=7
ii= 6, jj=7: l_30=0x01, l_34=0x01, l_20=7, l_1c=7
ii= 7, jj=0: l_30=0x80, l_34=0x40, l_20=1, l_1c=8
ii= 7, jj=1: l_30=0x40, l_34=0x20, l_20=2, l_1c=8
ii= 7, jj=2: l_30=0x20, l_34=0x10, l_20=3, l_1c=8
ii= 7, jj=3: l_30=0x10, l_34=0x08, l_20=4, l_1c=8
ii= 7, jj=4: l_30=0x08, l_34=0x04, l_20=5, l_1c=8
ii= 7, jj=5: l_30=0x04, l_34=0x02, l_20=6, l_1c=8
ii= 7, jj=6: l_30=0x02, l_34=0x01, l_20=7, l_1c=8
ii= 7, jj=7: l_30=0x01, l_34=0x40, l_20=1, l_1c=9
ii= 8, jj=0: l_30=0x80, l_34=0x20, l_20=2, l_1c=9
ii= 8, jj=1: l_30=0x40, l_34=0x10, l_20=3, l_1c=9
ii= 8, jj=2: l_30=0x20, l_34=0x08, l_20=4, l_1c=9
ii= 8, jj=3: l_30=0x10, l_34=0x04, l_20=5, l_1c=9
ii= 8, jj=4: l_30=0x08, l_34=0x02, l_20=6, l_1c=9
ii= 8, jj=5: l_30=0x04, l_34=0x01, l_20=7, l_1c=9
ii= 8, jj=6: l_30=0x02, l_34=0x40, l_20=1, l_1c=10
ii= 8, jj=7: l_30=0x01, l_34=0x20, l_20=2, l_1c=10
ii= 9, jj=0: l_30=0x80, l_34=0x10, l_20=3, l_1c=10
ii= 9, jj=1: l_30=0x40, l_34=0x08, l_20=4, l_1c=10
ii= 9, jj=2: l_30=0x20, l_34=0x04, l_20=5, l_1c=10
ii= 9, jj=3: l_30=0x10, l_34=0x02, l_20=6, l_1c=10
ii= 9, jj=4: l_30=0x08, l_34=0x01, l_20=7, l_1c=10
ii= 9, jj=5: l_30=0x04, l_34=0x40, l_20=1, l_1c=11
ii= 9, jj=6: l_30=0x02, l_34=0x20, l_20=2, l_1c=11
ii= 9, jj=7: l_30=0x01, l_34=0x10, l_20=3, l_1c=11
ii=10, jj=0: l_30=0x80, l_34=0x08, l_20=4, l_1c=11
ii=10, jj=1: l_30=0x40, l_34=0x04, l_20=5, l_1c=11
ii=10, jj=2: l_30=0x20, l_34=0x02, l_20=6, l_1c=11
ii=10, jj=3: l_30=0x10, l_34=0x01, l_20=7, l_1c=11
ii=10, jj=4: l_30=0x08, l_34=0x40, l_20=1, l_1c=12
ii=10, jj=5: l_30=0x04, l_34=0x20, l_20=2, l_1c=12
ii=10, jj=6: l_30=0x02, l_34=0x10, l_20=3, l_1c=12
ii=10, jj=7: l_30=0x01, l_34=0x08, l_20=4, l_1c=12
ii=11, jj=0: l_30=0x80, l_34=0x04, l_20=5, l_1c=12
ii=11, jj=1: l_30=0x40, l_34=0x02, l_20=6, l_1c=12
ii=11, jj=2: l_30=0x20, l_34=0x01, l_20=7, l_1c=12
ii=11, jj=3: l_30=0x10, l_34=0x40, l_20=1, l_1c=13
ii=11, jj=4: l_30=0x08, l_34=0x20, l_20=2, l_1c=13
ii=11, jj=5: l_30=0x04, l_34=0x10, l_20=3, l_1c=13
ii=11, jj=6: l_30=0x02, l_34=0x08, l_20=4, l_1c=13
ii=11, jj=7: l_30=0x01, l_34=0x04, l_20=5, l_1c=13
ii=12, jj=0: l_30=0x80, l_34=0x02, l_20=6, l_1c=13
ii=12, jj=1: l_30=0x40, l_34=0x01, l_20=7, l_1c=13
ii=12, jj=2: l_30=0x20, l_34=0x40, l_20=1, l_1c=14
ii=12, jj=3: l_30=0x10, l_34=0x20, l_20=2, l_1c=14
ii=12, jj=4: l_30=0x08, l_34=0x10, l_20=3, l_1c=14
ii=12, jj=5: l_30=0x04, l_34=0x08, l_20=4, l_1c=14
ii=12, jj=6: l_30=0x02, l_34=0x04, l_20=5, l_1c=14
ii=12, jj=7: l_30=0x01, l_34=0x02, l_20=6, l_1c=14
ii=13, jj=0: l_30=0x80, l_34=0x01, l_20=7, l_1c=14
ii=13, jj=1: l_30=0x40, l_34=0x40, l_20=1, l_1c=15
ii=13, jj=2: l_30=0x20, l_34=0x20, l_20=2, l_1c=15
ii=13, jj=3: l_30=0x10, l_34=0x10, l_20=3, l_1c=15
ii=13, jj=4: l_30=0x08, l_34=0x08, l_20=4, l_1c=15
ii=13, jj=5: l_30=0x04, l_34=0x04, l_20=5, l_1c=15
ii=13, jj=6: l_30=0x02, l_34=0x02, l_20=6, l_1c=15
ii=13, jj=7: l_30=0x01, l_34=0x01, l_20=7, l_1c=15
ii=14, jj=0: l_30=0x80, l_34=0x40, l_20=1, l_1c=16
ii=14, jj=1: l_30=0x40, l_34=0x20, l_20=2, l_1c=16
ii=14, jj=2: l_30=0x20, l_34=0x10, l_20=3, l_1c=16
ii=14, jj=3: l_30=0x10, l_34=0x08, l_20=4, l_1c=16
ii=14, jj=4: l_30=0x08, l_34=0x04, l_20=5, l_1c=16
ii=14, jj=5: l_30=0x04, l_34=0x02, l_20=6, l_1c=16
ii=14, jj=6: l_30=0x02, l_34=0x01, l_20=7, l_1c=16
ii=14, jj=7: l_30=0x01, l_34=0x40, l_20=1, l_1c=17
ii=15, jj=0: l_30=0x80, l_34=0x20, l_20=2, l_1c=17
ii=15, jj=1: l_30=0x40, l_34=0x10, l_20=3, l_1c=17
ii=15, jj=2: l_30=0x20, l_34=0x08, l_20=4, l_1c=17
ii=15, jj=3: l_30=0x10, l_34=0x04, l_20=5, l_1c=17
ii=15, jj=4: l_30=0x08, l_34=0x02, l_20=6, l_1c=17
ii=15, jj=5: l_30=0x04, l_34=0x01, l_20=7, l_1c=17
ii=15, jj=6: l_30=0x02, l_34=0x40, l_20=1, l_1c=18
ii=15, jj=7: l_30=0x01, l_34=0x20, l_20=2, l_1c=18
ii=16, jj=0: l_30=0x80, l_34=0x10, l_20=3, l_1c=18
ii=16, jj=1: l_30=0x40, l_34=0x08, l_20=4, l_1c=18
ii=16, jj=2: l_30=0x20, l_34=0x04, l_20=5, l_1c=18
ii=16, jj=3: l_30=0x10, l_34=0x02, l_20=6, l_1c=18
ii=16, jj=4: l_30=0x08, l_34=0x01, l_20=7, l_1c=18
ii=16, jj=5: l_30=0x04, l_34=0x40, l_20=1, l_1c=19
ii=16, jj=6: l_30=0x02, l_34=0x20, l_20=2, l_1c=19
ii=16, jj=7: l_30=0x01, l_34=0x10, l_20=3, l_1c=19
ii=17, jj=0: l_30=0x80, l_34=0x08, l_20=4, l_1c=19
ii=17, jj=1: l_30=0x40, l_34=0x04, l_20=5, l_1c=19
ii=17, jj=2: l_30=0x20, l_34=0x02, l_20=6, l_1c=19
ii=17, jj=3: l_30=0x10, l_34=0x01, l_20=7, l_1c=19
ii=17, jj=4: l_30=0x08, l_34=0x40, l_20=1, l_1c=20
ii=17, jj=5: l_30=0x04, l_34=0x20, l_20=2, l_1c=20
ii=17, jj=6: l_30=0x02, l_34=0x10, l_20=3, l_1c=20
ii=17, jj=7: l_30=0x01, l_34=0x08, l_20=4, l_1c=20
ii=18, jj=0: l_30=0x80, l_34=0x04, l_20=5, l_1c=20
ii=18, jj=1: l_30=0x40, l_34=0x02, l_20=6, l_1c=20
ii=18, jj=2: l_30=0x20, l_34=0x01, l_20=7, l_1c=20
ii=18, jj=3: l_30=0x10, l_34=0x40, l_20=1, l_1c=21
ii=18, jj=4: l_30=0x08, l_34=0x20, l_20=2, l_1c=21
ii=18, jj=5: l_30=0x04, l_34=0x10, l_20=3, l_1c=21
ii=18, jj=6: l_30=0x02, l_34=0x08, l_20=4, l_1c=21
ii=18, jj=7: l_30=0x01, l_34=0x04, l_20=5, l_1c=21
ii=19, jj=0: l_30=0x80, l_34=0x02, l_20=6, l_1c=21
ii=19, jj=1: l_30=0x40, l_34=0x01, l_20=7, l_1c=21
ii=19, jj=2: l_30=0x20, l_34=0x40, l_20=1, l_1c=22
ii=19, jj=3: l_30=0x10, l_34=0x20, l_20=2, l_1c=22
ii=19, jj=4: l_30=0x08, l_34=0x10, l_20=3, l_1c=22
ii=19, jj=5: l_30=0x04, l_34=0x08, l_20=4, l_1c=22
ii=19, jj=6: l_30=0x02, l_34=0x04, l_20=5, l_1c=22
ii=19, jj=7: l_30=0x01, l_34=0x02, l_20=6, l_1c=22
ii=20, jj=0: l_30=0x80, l_34=0x01, l_20=7, l_1c=22
ii=20, jj=1: l_30=0x40, l_34=0x40, l_20=1, l_1c=23
ii=20, jj=2: l_30=0x20, l_34=0x20, l_20=2, l_1c=23
ii=20, jj=3: l_30=0x10, l_34=0x10, l_20=3, l_1c=23
ii=20, jj=4: l_30=0x08, l_34=0x08, l_20=4, l_1c=23
ii=20, jj=5: l_30=0x04, l_34=0x04, l_20=5, l_1c=23
ii=20, jj=6: l_30=0x02, l_34=0x02, l_20=6, l_1c=23
ii=20, jj=7: l_30=0x01, l_34=0x01, l_20=7, l_1c=23
ii=21, jj=0: l_30=0x80, l_34=0x40, l_20=1, l_1c=24
ii=21, jj=1: l_30=0x40, l_34=0x20, l_20=2, l_1c=24
ii=21, jj=2: l_30=0x20, l_34=0x10, l_20=3, l_1c=24
ii=21, jj=3: l_30=0x10, l_34=0x08, l_20=4, l_1c=24
ii=21, jj=4: l_30=0x08, l_34=0x04, l_20=5, l_1c=24
ii=21, jj=5: l_30=0x04, l_34=0x02, l_20=6, l_1c=24
ii=21, jj=6: l_30=0x02, l_34=0x01, l_20=7, l_1c=24
ii=21, jj=7: l_30=0x01, l_34=0x40, l_20=1, l_1c=25
ii=22, jj=0: l_30=0x80, l_34=0x20, l_20=2, l_1c=25
ii=22, jj=1: l_30=0x40, l_34=0x10, l_20=3, l_1c=25
ii=22, jj=2: l_30=0x20, l_34=0x08, l_20=4, l_1c=25
ii=22, jj=3: l_30=0x10, l_34=0x04, l_20=5, l_1c=25
ii=22, jj=4: l_30=0x08, l_34=0x02, l_20=6, l_1c=25
ii=22, jj=5: l_30=0x04, l_34=0x01, l_20=7, l_1c=25
ii=22, jj=6: l_30=0x02, l_34=0x40, l_20=1, l_1c=26
ii=22, jj=7: l_30=0x01, l_34=0x20, l_20=2, l_1c=26
picoCTF{0n3_bi7_4t_a_7im3}
```
