#include <unistd.h>

// libc をスタティックリンクすること
// $ gcc -static -o execve_c.out execve_c.c

int main( int argc, char *argv[] )
{
    char *args[] = { "/bin/sh", NULL };
    
    // 第1引数：プログラムパス → 必ずパスで指定すること (環境変数 PATH は参照されない)
    // 第2引数：プログラムに渡す引数の配列 (NULL を指定しても普通に動いた)
    // 第3引数：環境変数の配列
    execve( args[0], args, NULL );
    //execve( args[0], NULL, NULL );
}
