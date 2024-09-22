#include <stdio.h>

extern char **environ;

int data0;
int data1 = 10;

int main(int argc, char *argv[])
{
    char c;
    
    printf("environ:\t%p\n", environ);
    printf("argv:\t\t%p\n", argv);
    printf("stack:\t\t%p\n", &c);
    
    printf("bss:\t\t%p\n", &data0);
    printf("data:\t\t%p\n", &data1);
    
    return 0;
}
