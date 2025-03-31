#include <stdio.h>

int main( int argc, char *argv[] )
{
    // 引数の位置を %m$ で指定可能
    printf( "[%4$d] [%2$d] %d [%3$d] %d [%3$d] [%1$d]\n\n", 1, 2, 3, 4 );
    
    // * により、引数で、最小フィールド幅を指定可能
    printf( "%0*x\n\n", 16, 0xdeadbeef );
    
    // *m$ で、最小フィールド幅の引数の位置を指定可能
    printf( "%0*2$x\n\n", 0xbeef, 8 );
    
    // 小数の精度として、小数点以下の桁数を指定可能
    printf( "%.4f\n\n", 3.141592 );
    
    // 文字列の精度指定の場合、ヌル文字で終端しなくていい
    printf( "%.8s\n\n", "aaaabbbbccccdddd" );
    
    // 最小フィールド幅の引数の位置指定と精度の引数の位置指定
    printf( "%*3$.*2$s\n\n", "xxxxyyyyzzzz", 8, 16 );
}
