#include "kernel/types.h"
#include "user/user.h"
#include "kernel/fcntl.h"

// demonstrate buffer overflow
// input:
// AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
// (67 A's)

int main(int argc, char **argv)
{
    volatile int modified;
    char buffer[64];

    modified = 0;
    gets(buffer, 100);

    if(modified != 0) {
        printf("you have changed the 'modified' variable\n");
        return 0;
    } else {
        printf("Try again?\n");
        return -1;
    }
}