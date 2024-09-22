#include <stdio.h>
#include <stdlib.h>

int sub( int data )
{
  int data2;
  
  printf( "input data2: " );
  
  scanf( "%d", &data2 );
  
  return data + data2;
}

int main( int argc, void *argv[] )
{
  int ret, data;
  char buf[20], *mbuf;
  
  mbuf = malloc( 20 );
  
  printf( "  main: %p\n", main );
  printf( "   buf: %p\n",  buf );
  printf( "  mbuf: %p\n", mbuf );
  printf( "malloc: %p\n", malloc );
  
  printf( "input data: " );
  
  scanf( "%d", &data );
  
  ret = sub( data );
  
  printf( "result: %d", ret );
  
  if( ret > 0 )
    return 0;
  else
    return 1;
}
