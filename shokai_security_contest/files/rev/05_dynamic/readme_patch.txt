#### 28.1�F�v���O�����Ƀp�b�`�𓖂Ă�

�v���O�����̃o�C�i�����ꕔ�ύX���āA�v���O�����̓����ς��邱�Ƃ�������Ă��܂��B���Ђł́AIDA ���g�������@��������Ă��܂��B

IDA �́A�v���O�����̃o�C�i����ύX���Ă��A�ύX��̃o�C�i�����G�N�X�|�[�g����@�\�����������ł����A�ύX�O�ƕύX��̍��ق͏o�͂ł��邻���ł��B
���̍��ق��t�@�C���o��(program.dif)���āA�o�C�i����ύX���� Python�X�N���v�g���Љ��Ă��܂��B

����AGhidra �ɂ́A�ύX��̃o�C�i�����G�N�X�|�[�g����@�\������悤�ł��B
�Q�l���Ђ́u�}�X�^�����OGhidra �\��b����w�ԃ��o�[�X�G���W�j�A�����O���S�}�j���A���v�� 22�͂́u�o�C�i���̃p�b�`�v�ɉ��������܂��B
��������Ȃ���A������Ƃ���Ă݂܂��B

�܂��Amain�֐��̋t�A�Z���u���������܂��B
0x400768�Ԓn�ŁAauthenticate�֐������s����܂��B
���̎��̍s�itest eax,eax�j�́AAND ���Ƃ��āA���ʂ��[�����ǂ��������W�X�^�ɔ��f���܂��B
���̎��̍s�ŁA�[���Ȃ�A0x40077f�Ԓn�ɔ�сA�ُ폈���ɂȂ�A�[������Ȃ���ΐ��폈���i�p�X���[�h��v�j�ɂȂ�܂��B

���̍s�𔽓]������΁A�Ԉ�����p�X���[�h����͂���ƁA�p�X���[�h����v�����A�Ƃ������ʂɏo���܂��B
��̓I�ɂ́A0x40076f�Ԓn�� `je 0x40077f <main+101>` �� jnz �ɕύX�������Ƃ������Ƃł��B

```asm
pwndbg> disassemble main
Dump of assembler code for function main:
   0x000000000040071a <+0>:     push   rbp
   0x000000000040071b <+1>:     mov    rbp,rsp
   0x000000000040071e <+4>:     sub    rsp,0x40
   0x0000000000400722 <+8>:     mov    DWORD PTR [rbp-0x34],edi
   0x0000000000400725 <+11>:    mov    QWORD PTR [rbp-0x40],rsi
   0x0000000000400729 <+15>:    mov    rax,QWORD PTR fs:0x28
   0x0000000000400732 <+24>:    mov    QWORD PTR [rbp-0x8],rax
   0x0000000000400736 <+28>:    xor    eax,eax
   0x0000000000400738 <+30>:    lea    rdi,[rip+0xf5]        # 0x400834
   0x000000000040073f <+37>:    mov    eax,0x0
   0x0000000000400744 <+42>:    call   0x400550 <printf@plt>
   0x0000000000400749 <+47>:    lea    rax,[rbp-0x30]
   0x000000000040074d <+51>:    mov    rsi,rax
   0x0000000000400750 <+54>:    lea    rdi,[rip+0xee]        # 0x400845
   0x0000000000400757 <+61>:    mov    eax,0x0
   0x000000000040075c <+66>:    call   0x400560 <__isoc99_scanf@plt>
   0x0000000000400761 <+71>:    lea    rax,[rbp-0x30]
   0x0000000000400765 <+75>:    mov    rdi,rax
   0x0000000000400768 <+78>:    call   0x4006ab <authenticate>
   0x000000000040076d <+83>:    test   eax,eax
   0x000000000040076f <+85>:    je     0x40077f <main+101>
   0x0000000000400771 <+87>:    lea    rdi,[rip+0xd2]        # 0x40084a
   0x0000000000400778 <+94>:    call   0x400520 <puts@plt>
   0x000000000040077d <+99>:    jmp    0x40078b <main+113>
   0x000000000040077f <+101>:   lea    rdi,[rip+0xd9]        # 0x40085f
   0x0000000000400786 <+108>:   call   0x400520 <puts@plt>
   0x000000000040078b <+113>:   mov    eax,0x0
   0x0000000000400790 <+118>:   mov    rdx,QWORD PTR [rbp-0x8]
   0x0000000000400794 <+122>:   xor    rdx,QWORD PTR fs:0x28
   0x000000000040079d <+131>:   je     0x4007a4 <main+138>
   0x000000000040079f <+133>:   call   0x400540 <__stack_chk_fail@plt>
   0x00000000004007a4 <+138>:   leave
   0x00000000004007a5 <+139>:   ret
End of assembler dump.
```

�ꉞ�A0x40084a �� 0x40085f �̂ǂ��炪����p�X�Ȃ̂���������Ȃ��̂ŁA��������m�F���Ă����܂��B0x40084a �̕����A����p�X�ł����B

```sh
pwndbg> x/20c 0x40084a
0x40084a:       80 'P'  97 'a'  115 's' 115 's' 119 'w' 111 'o' 114 'r' 100 'd'
0x400852:       32 ' '  105 'i' 115 's' 32 ' '  99 'c'  111 'o' 114 'r' 114 'r'
0x40085a:       101 'e' 99 'c'  116 't' 33 '!'
```

�ł́AGhidra �Ńp�b�`�𓖂ĂĂ݂܂��B0x40076f�Ԓn�ŉE�N���b�N���āAPatch Instruction ���N���b�N���܂��B
����ƁA���߂�ҏW�ł���̂ŁAJE �� JNZ �ɕύX���܂��BJNZ �ɕύX����ƁA���߂̃o�C�g�񂪏o��̂ŁA�������ς��Ȃ����Ƃ��m�F���Ď��s���܂��B

�}�Fghidra_patch.png

���̌�A�ۑ����āiFile �� Save All�j�A�G�N�X�|�[�g���܂��iFile �� Export Program... �ŁAFormat �� Original File �ɂ���j�B
�G�N�X�|�[�g���ʂ��m�F���܂��B1byte�����������ɂȂ��Ă��܂��i74��75�ɕω��j

�}�Fwinmerge_patch.png


```sh
$ hexdump -C program > program.hex

$ hexdump -C program_patch > program_patch.hex

$ diff program.hex program_patch.hex
--- program.hex 2024-12-28 20:23:36.566180939 +0900
+++ program_patch.hex   2024-12-28 20:23:44.252843329 +0900
@@ -116,7 +116,7 @@
 00000730  00 00 48 89 45 f8 31 c0  48 8d 3d f5 00 00 00 b8  |..H.E.1.H.=.....|
 00000740  00 00 00 00 e8 07 fe ff  ff 48 8d 45 d0 48 89 c6  |.........H.E.H..|
 00000750  48 8d 3d ee 00 00 00 b8  00 00 00 00 e8 ff fd ff  |H.=.............|
-00000760  ff 48 8d 45 d0 48 89 c7  e8 3e ff ff ff 85 c0 74  |.H.E.H...>.....t|
+00000760  ff 48 8d 45 d0 48 89 c7  e8 3e ff ff ff 85 c0 75  |.H.E.H...>.....u|
 00000770  0e 48 8d 3d d2 00 00 00  e8 a3 fd ff ff eb 0c 48  |.H.=...........H|
 00000780  8d 3d d9 00 00 00 e8 95  fd ff ff b8 00 00 00 00  |.=..............|
 00000790  48 8b 55 f8 64 48 33 14  25 28 00 00 00 74 05 e8  |H.U.dH3.%(...t..|
```

�p�b�`�𓖂Ă��o�C�i�������s���Ă݂܂��BOK�ł��B

```sh
$ ./program_patch
Enter password: 0123456789
Password is correct!
```

����̏ꍇ�͕ύX��̖��߂̃T�C�Y���A�ύX�O�̖��߂̃T�C�Y�Ɠ����������̂ŁA�ȒP�Ƀp�b�`�𓖂Ă邱�Ƃ��o���܂����B
�����A�ύX��̖��߂̃T�C�Y���A�ύX�O�̖��߂̃T�C�Y�����������ꍇ�́A�󂢂��Ƃ���ɁAnop���߂𖄂߂�΂����ł��ˁB
�ύX��̖��߂̃T�C�Y���A�ύX�O�̖��߂̃T�C�Y�����傫���ꍇ�͓���ł��B
���̃P�[�X�ɂ��Ă��Q�l�����́u�}�X�^�����OGhidra �\��b����w�ԃ��o�[�X�G���W�j�A�����O���S�}�j���A���v�ɉ��������̂ŁA�K�v�ɂȂ����痝���������Ǝv���܂��B

