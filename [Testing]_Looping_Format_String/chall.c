#include <stdio.h>
#include <string.h>

int main()
{
    char buf[0x40];
    
    setbuf(stdin, 0);
    setbuf(stdout, 0);
    setbuf(stderr, 0);

    memset(buf, 0, 0x40); // prevent stack pointer available in stack
    read(0, buf, 0x40);   // no stack buffer overflow here
    printf(buf);          // attack this
}