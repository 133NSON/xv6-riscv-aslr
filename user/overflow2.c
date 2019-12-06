#include "kernel/types.h"
#include "user/user.h"
#include "kernel/fcntl.h"

// demonstrate overwrite return pointer attack

void func1() {
    char buf[8] = {0};
    printf("buf addr: 0x%x\n", &buf);
    gets(buf, 80);
}

void give_shell() {
    printf("success");
    char* args[2] = {0};
    args[0] = "sh";
    exec("sh", args);
}

int main(int argc, char **argv)
{
    func1();
    exit(0);
}
