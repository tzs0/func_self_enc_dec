#include <inttypes.h>
#include <stdio.h>
#include <stdint.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <regex.h>
#include <setjmp.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <elf.h>
#include <sys/mman.h>
#include <link.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>


#define my_printf(fmt, ...) 		printf("[%s %s %d]"fmt, __FILE__, __func__, __LINE__, ##__VA_ARGS__)

int main(int argc, char * * argv)
{
    my_printf("iamhere\n");
    lib_func0();
    my_printf("exit\n");
    
    return 0;
}

