#include "kernel/types.h"
#include "user/user.h"
#include "kernel/fcntl.h"

// print out addresses
void func();

int a = 20;

int main(int argc, char **argv)
{
    char buffer[64];
    printf("stack: 0x%x\n", &buffer);
    printf("func addr: 0x%x\n", &func);
    printf("var addr: 0x%x\n", &a);
    exit(0);
}

void func() {
    printf("func");
}