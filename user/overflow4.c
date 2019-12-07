#include "kernel/types.h"
#include "user/user.h"
#include "kernel/fcntl.h"

// demonstrate ret2libc attack
extern char uthread_switch[];

void func1(int fd) {
    char buf[0x10] = {0};
    printf("buf: 0x%x\n", &buf);
    read(fd, buf, 128);

}

void win(){
    printf("new shell executed.\n");
    char * argv[] = { "sh", 0 };
    exec("sh", argv);
    exit(1);
}

void win2(char inp){
    printf("%d", inp);
    if (inp == 'A'){
        printf("successfull mfmfmfmf hell fucking ya");
    }
    printf("new shell executed2.\n");
    char * argv[] = { "sh", 0 };
    exec("sh", argv);
    exit(1);
}

int main(int argc, char **argv)
{
    int fd = open(argv[1], O_RDONLY);
    printf("argv: 0x%x\n", &argv[1]);
    func1(fd);
    exit(0);
}