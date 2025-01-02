Medium �̖��ł��B

�X�V���ꂽ�o�C�i���t�@�C���icrackme100�j�� 1�_�E�����[�h�ł��܂��B

�܂��A�Ō�̓T�[�o���N�����Ď��s����K�v������悤�ł��B

�\�w��͂��s���܂��Bstrings�R�}���h�Ńt���O�������Ă܂����A���[�J���t�@�C���p�̃t���O�Ƃ������Ƃł��傤���B

```sh
$ file crackme100 
crackme100: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=f680c44f890f619e9d88949f9048709d008b18f1, for GNU/Linux 3.2.0, with debug_info, not stripped

$ checksec --file=crackme100
RELRO          STACK CANARY     NX          PIE     RPATH     RUNPATH     Symbols     FORTIFY  Fortified  Fortifiable  FILE
Partial RELRO  No canary found  NX enabled  No PIE  No RPATH  No RUNPATH  40 Symbols  No       0          1            crackme100

$ strings crackme100 | grep pico
picoCTF{sample_flag}
```

�܂��A���s���Ă݂܂��B�������p�X���[�h����͂���K�v�����肻���ł��B

```sh
$ ./crackme100
Enter the secret password: aaa
FAILED!
```

Ghidra ���g���āA�\�[�X�����Ă����܂��B�Ȃ񂩐����h�Ȗ����Ċ����ł��B

��d���[�v�̂Ƃ����ǂ݉����Ă݂܂��B�O���� 3��A������ �z��ϐ��� output �̕������Ȃ̂� 50����s���ꂻ���ł��B

�����������Ȃ肻���Ȃ̂ŁA�\�[�X�R�[�h�̉��ɏ����Ă����܂��B

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

���[�v�̓����� 4�s���ڂ������܂��B

1�s�ڂ́A���Z�q�̗D�揇�ʂ𐳂�������K�v������̂Ŋ��ʂ�t���܂��B�܂��A`i_1` �� 0 ���� 49 ���Ƃ�̂ŁA`% 0xff` �͖����ł��܂��B

`uVar1 = (((i_1 % 0xff) >> 1) & 0x55U) + ((i_1 % 0xff) & 0x55U);`

����āA�ȉ��̂悤�ɊȒP�ɂł��܂��B

`uVar1 = ((i_1 >> 1) & 0x55U) + (i_1 & 0x55U);`

���[��A���̂����͖��d�ł����B��߂܂��B

4�s�̂����Ainput �ȊO�͒l�����܂��Ă��邱�ƂƁAi �� 4�s�ɏo�Ă��Ȃ����ƁA���� input �̌v�Z�ɁA���� input ���֌W���Ȃ����Ƃ�������܂��B

�܂�A���� input �̏ꍇ�ɁA���� 4�s�� 3��A���ł�������ʂƓ����ł��B

�v���O������ ASCII�R�[�h�𑍓�����Ōv�Z����̂�������������܂���B�p�����������ł��������ł����B

Python�X�N���v�g���������܂��B

C���ꂩ��APython �ɕϊ����邾���ł����B

��������s����ƁA�������p�X���[�h���\������܂��B

�T�[�o�œ����p�X���[�h����͂���ƁA�t���O���\������܂����B

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


����Ă݂܂��B

```sh
$ python crackme100.py
ret=kdugtjvgrknflqrdgb`d_sdqwmnmtmjptjr`bv`tpelejfuprc

$ ./crackme100
Enter the secret password: kdugtjvgrknflqrdgb`d_sdqwmnmtmjptjr`bv`tpelejfuprc
SUCCESS! Here is your flag: picoCTF{sample_flag}
```

�T�[�o�ɑ΂��Ď��{����ƃt���O���\������܂��B

