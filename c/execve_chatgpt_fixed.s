.section .data
args:
    .string "/bin/sh"      // "/bin/sh" 文字列
    .quad 0                // NULL 終端

.section .text
.globl _start
_start:
    // 引数の設定
    ldr x0, =args         // x0 に "/bin/sh" のアドレスをロード
    mov x1, =args         // これはアセンブルエラーになる、argsのアドレスをx1に入れたいけど、やり方が分からない
    mov x2, #0            // x2 に NULL をセット (環境変数なし)

    // execve システムコールの呼び出し
    mov x8, #221          // x8 に execve のシステムコール番号をセット (221)
    svc #0                // システムコールの実行

    // プログラム終了（エラー処理）
    mov x8, #93           // x8 に exit のシステムコール番号をセット (93)
    mov x0, #0            // x0 に終了コードをセット (0)
    svc #0                // システムコールの実行
