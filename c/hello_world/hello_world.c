#include <stdio.h>

int sub( void )
{
  int data;
  
  printf( "input data: " );
  
  scanf( "%d", &data );
  
  return data;
}

int main( int argc, void *argv[] )
{
  int ret;
  
  ret = sub();
  
  if( ret > 0 )
    return 0;
  else
    return 1;
}
