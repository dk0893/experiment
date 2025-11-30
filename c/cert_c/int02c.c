#include <stdio.h>
#include <stdint.h>
#include <limits.h>

// 整数拡張 (Integer Promotions)
void integer_promotions( void )
{
    signed char cresult, c1, c2, c3;
    
    c1 = 100;
    c2 = 3;
    c3 = 4;
    
    // 普通に考えると、c1 * c2 で、singned char の上限の 127 を超えるように見えるが、
    // 整数拡張が行われるため、そうはならない
    // 
    // c1、c2、c3 は、それぞれ int型に整数拡張される
    // 100 * 3 = 300、300 / 4 = 75 になり、cresult に格納される
    cresult = c1 * c2 / c3;
    
    printf( "integer_promotions(): c1(100) * c2(3) / c3(4) -> %d\n", cresult );
}

// 整数拡張 (Integer Promotions)
void integer_promotions_NG( void )
{
    uint8_t port = 0x5a;
    uint8_t result_8 = ( ~port ) >> 4;
    
    printf( "integer_promotions_NG(): ( ~port(0x5a) ) >> 4 -> 0x%02x\n", result_8 );
    
    printf( "integer_promotions_NG(): ~port -> 0x%x, ~(uint8_t)port -> 0x%x, ~port >> 4 -> 0x%x\n", ~port, ~(uint8_t)port, ~port >> 4 );
}

void integer_promotions_OK( void )
{
    uint8_t port = 0x5a;
    uint8_t result_8 = (uint8_t)( ~port ) >> 4;
    
    printf( "integer_promotions_OK(): (uint8_t)( ~port(0x5a) ) >> 4 -> 0x%02x\n", result_8 );
}

// 通常の算術型変換 (Arithmetic Conversions)
void arithmetic_conversions_3_NG( void )
{
    int si = -1;
    unsigned int ui = 1;
    
    // 3. 符号付き≦符号無し -> 符号付きが、符号無しに変換される
    
    // -1 は、符号無しに変換されると、UINT_MAX に変換されてしまう
    printf( "arithmetic_conversions_3_NG(): si(-1) < ui(1) -> %d\n", si < ui );
    
    printf( "arithmetic_conversions_3_NG(): si -> %u, UINT_MAX -> %u\n", si, UINT_MAX );
}

void arithmetic_conversions_3_OK( void )
{
    int si = -1;
    unsigned int ui = 1;
    
    // 3. 符号付き≦符号無し -> 符号付きが、符号無しに変換される
    
    // int同士(1. 同じ型)なので型変換されなくなる
    // ただし、これは、ui が int で表現できる値であることが
    // あらかじめ、分かっている場合にのみ、使える実装であることに注意
    printf( "arithmetic_conversions_3_OK(): si(-1) < (int)ui(1) -> %d\n", si < (int)ui );
}

void arithmetic_conversions_3_OK_2( void )
{
    int si = -1;
    unsigned int ui = 1;
    
    // 3. 符号付き≦符号無し -> 符号付きが、符号無しに変換される
    
    // ui が int で表現できる値であるかどうかが分からない場合の実装
    // 掲載されている適合コードでは、2番目の si に (unsigned)si と
    // キャストされていたが、型変換で unsigned に変換されるので不要だと思う
    printf( "arithmetic_conversions_3_OK_2(): si(-1) < 0 || si(-1) < ui(1) -> %d\n", si < 0 || si < ui );
}

void arithmetic_conversions_4_or_5( void )
{
    long sl = -1;            // signed 64-bit or signed 32bit (値 = -1)
    unsigned int ui = 1;     // unsigned 32-bit (値 = 1)
    
    // 4. 符号付き＞符号無し ※符号付きの型が、符号無しの型の全ての値を表現できる場合
    // 5. 符号付き＞符号無し ※符号付きの型が、符号無しの型の全ての値を表現できない場合
    printf( "arithmetic_conversions_4_or_5(): long sl(-1) < unsigned int ui(1) -> %d\n", sl < ui );
}

void arithmetic_conversions_4( void )
{
    long sl = -1;            // signed 64-bit (値 = -1)
    unsigned int ui = 1;     // unsigned 32-bit (値 = 1)
    
    // 4. 符号付き＞符号無し ※符号付きの型が、符号無しの型の全ての値を表現できる場合
    long l = sl + ui;
    
    printf( "arithmetic_conversions_4(): sl(-1) + ui(1) -> %ld\n", l );
}

void arithmetic_conversions_5( void )
{
    long sl = -10;             // signed 32-bit (32bitOSの場合)
    unsigned int ui = 5u;     // unsigned 32-bit
    
    long l = sl + ui;  // ルール5が適用され、符号付きの型(long)に対応する符号無しの型(unsigned long)に変換する
    
    printf( "arithmetic_conversions_5(): sl(-10) + ui(5) -> %ld\n", l );
}

void test_sizeof( void )
{
    long sl = -10;
    
    printf( "test_sizeof(): sizeof(s) -> %d\n", sizeof(sl) );  // 32bit OS の場合は、sizeof() は unsigned int
    printf( "test_sizeof(): sizeof(s) -> %ld\n", sizeof(sl) ); // 64bit OS の場合は、sizeof() は unsigned long int
}

int main( int argc, void *argv[] )
{
    integer_promotions();
    
    integer_promotions_NG();
    
    integer_promotions_OK();
    
    arithmetic_conversions_3_NG();
    
    arithmetic_conversions_3_OK();
    
    arithmetic_conversions_3_OK_2();
    
    arithmetic_conversions_4_or_5();
    
    arithmetic_conversions_4();
    
    arithmetic_conversions_5();
    
    test_sizeof();
    
    return 0;
}
