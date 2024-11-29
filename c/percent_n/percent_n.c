#include <stdio.h>

int main( int argc, void *argv[] )
{
    unsigned int num = 0;
    
    printf( "123456%n\n", &num );
    
    printf( "%d\n", num );
}
