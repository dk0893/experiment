#### Shellcode

�T�[�o�ƃ��[�J���t�@�C���Ƃ�����܂��B���ʂɓ�� pwn �̖����ۂ��ł��B

<figure class="figure-image figure-image-fotolife" title="Pwn��Shellcode���">[f:id:daisuke20240310:20240918222118p:plain:alt=Pwn��Shellcode���]<figcaption>Pwn��Shellcode���</figcaption></figure>

�𓀂���ƁAshellcode �Ƃ����t�@�C���������܂��B

�܂��A�\�w��͂ł��Bstrip ����ĂȂ��āA�X�^�b�N���s��������Ă܂��B���s���Ă݂܂������A�悭������܂���B�ςȃt�@�C���iWindows�v���O�����j����Ȃ��ėǂ������ł��i�΁j�B

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

Ghidra �Ō��Ă݂܂��Bmain�֐������̂悤�ł��B�閧�̊֐������ɂ���܂���B

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

�X�^�b�N�o�b�t�@�I�[�o�[�t���[���A���������čU������̂͊ԈႢ�Ȃ��ł����A�ǂ�����΂�����ł��傤���B���A�V�F���R�[�h��p�ӂ��Ă��������Ə�����Ă܂��ˁB�Ȃ�قǂł��B

[�ȑO1](https://daisuke20240310.hatenablog.com/entry/shell2)�A[�ȑO2](https://daisuke20240310.hatenablog.com/entry/shell3) �ŁA������V�F���R�[�h�� ARM64�p�ł����B����́Ax86-64 �ō��K�v������܂��B

�ȉ��̋L���ŁA�V�F���R�[�h�����܂����B

[https://daisuke20240310.hatenablog.com/entry/chgbook2:embed:cite]

`flag{It_is_our_ch0ices_that_show_what_w3_truly_are_far_m0re_thAn_our_abi1ities}` �ł����B

