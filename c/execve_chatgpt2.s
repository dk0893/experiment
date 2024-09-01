.global _start           // エントリーポイントをグローバルとして定義

_start:
    ldr x0, =binsh       // "/bin/sh" を含む文字列のアドレスをレジスタ x0 にセット

    adr x1, argv         // argv の配列のアドレスをレジスタ x1 にセット
    mov x2, xzr          // x2 レジスタを NULL に設定（envp のため）

    mov x8, #221         // execve システムコール番号を x8 にセット (221はexecveのシステムコール番号)
    svc #0               // システムコールの呼び出し

binsh:
    .asciz "/bin/sh"     // シェルのパスをNULL終端文字列としてメモリに定義

argv:
    .quad binsh          // argv[0] は "/bin/sh" を指す
    .quad 0              // argv[1] は NULL を指す
