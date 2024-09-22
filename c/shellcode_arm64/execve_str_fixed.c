#include <stdio.h>
#include <unistd.h>
#include <sys/mman.h>  // mprotect関数を使用するために必要

char shellcode[] = "\x08\x01\x00\x58\xe2\x03\x1f\xaa\xe0\x03\x00\x91\xe8\x0b\xbf\xa8\xe1\x03\x00\x91\xe0\x0b\x00\xa9\xa8\x1b\x80\xd2\x01\x00\x00\xd4\x2f\x62\x69\x6e\x2f\x73\x68\x00";

int main()
{
    // メモリページサイズを取得
    long page_size = sysconf( _SC_PAGESIZE );
    
    printf( "page_size=0x%x\n", page_size );
    
    if( mprotect((void *)0x490000, 0x2000, PROT_READ | PROT_WRITE | PROT_EXEC) == -1 ){
        perror( "mprotect failed" );
        return 1;
    }
    
    ( (void (*)())shellcode )();
}
