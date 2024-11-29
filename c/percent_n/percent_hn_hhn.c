#include <stdio.h>

int main( int argc, void *argv[] )
{
    unsigned char  hhn = 0;
    unsigned short hn  = 0;
    unsigned int   n   = 0;
    
    printf( "123%hhn\n",    &hhn );
    printf( "123456%hn\n",  &hn );
    printf( "12345678%n\n", &n );
    
    printf( "%d\n", hhn );
    printf( "%d\n", hn );
    printf( "%d\n", n );
}
