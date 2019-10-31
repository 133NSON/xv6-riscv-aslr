#include "kernel/types.h"
#include "kernel/stat.h"
#include "user/user.h"

int
main(int argc, char *argv[])
{
    printf("begin\n");
    printf("random number: %d\n", random(1, 10));
    exit(0);
}