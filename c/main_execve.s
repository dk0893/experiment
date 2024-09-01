00000000004006d4 <main>:
  4006d4:  a9bd7bfd   stp  x29, x30, [sp, #-48]!         // スタック退避
  4006d8:  910003fd   mov  x29, sp                       // x29 ← sp         コピー
  4006dc:  b9001fe0   str  w0,  [sp, #28]                // w0  → [sp + 28]  1を[SP+28]にセット (32bit)
  4006e0:  f9000be1   str  x1,  [sp, #16]                // x1  → [sp + 16]  0x0000007fffffef98を[sp+16]にセット
  4006e4:  f00002a0   adrp x0,  457000 <_nl_archive_subfreeres+0xe0> // x0 ← 0x457000
  4006e8:  91092000   add  x0,  x0, #0x248               // x0  ← x0 + 0x248 (0x457000 + 0x248)
  4006ec:  f90013e0   str  x0,  [sp, #32]                // x0  → [sp + 32]  0x0000000000457248を[sp+32]にセット
  4006f0:  f90017ff   str  xzr, [sp, #40]                // #0  → [sp + 40]  0を[sp+40]にセット
  4006f4:  f94013e0   ldr  x0,  [sp, #32]                // x0  ← [sp + 32]  第1引数に0x0000000000457248をセット
  4006f8:  910083e1   add  x1,  sp, #0x20                // x1  ← sp + 20    第2引数に0x0000007fffffedd0をセット
  4006fc:  d2800002   mov  x2,  #0x0                     // #0                第3引数にNULLをセット
  400700:  94002660   bl   40a080 <__execve>
  400704:  52800000   mov  w0,  #0x0                     // #0
  400708:  a8c37bfd   ldp  x29, x30, [sp], #48
  40070c:  d65f03c0   ret

000000000040a080 <__execve>:
  40a080:  d503201f   nop
  40a084:  d2801ba8   mov   x8, #0xdd                    // #221
  40a088:  d4000001   svc   #0x0                         // システムコール
  40a08c:  b13ffc1f   cmn   x0, #0xfff
  40a090:  54000042   b.cs  40a098 <__execve+0x18>  // b.hs, b.nlast
  40a094:  d65f03c0   ret
  40a098:  14000e02   b     40d8a0 <__syscall_error>
  40a09c:  d503201f   nop
