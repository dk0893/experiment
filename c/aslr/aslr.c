#include <stdio.h>

int main( int argc, void *argv[] )
{
    printf( "printf: %p\n", printf );
    printf( "puts: %p\n",   puts );
    //printf( "system: %p\n", system );
    //printf( "execve: %p\n", execve );
}
