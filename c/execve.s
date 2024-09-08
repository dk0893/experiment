.global _start           // エントリーポイントをグローバルとして定義

_start:
    ldr x8, binsh         // "/bin/sh" を含む文字列を x8 にセット
    mov x2, xzr            // x2 レジスタを NULL に設定
    mov x0, sp             // x0 に sp の値をセット (第1引数)
    stp x8, x2, [sp], #-16 // x8("/bin/sh") と x2(NULL) の値をスタックにプッシュ (ポストインデックス) ※x2 は不要かも
    
    mov x1, sp             // x1 に sp の値をセット (第2引数)
    stp x0, x2, [sp, #0]   // x0("/bin/sh" のアドレス) と x2(NULL) の値をスタックにプッシュ (sp は動かない)
    
    mov x8, #221         // execve システムコール番号を x8 にセット (221はexecveのシステムコール番号)
    svc #0               // システムコールの呼び出し

binsh:
    .asciz "/bin/sh"     // シェルのパスをNULL終端文字列としてメモリに定義
