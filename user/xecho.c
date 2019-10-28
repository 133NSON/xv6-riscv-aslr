// user program to echo hex code, useful for breaking things

// call by running `xecho {HEX}`, where {HEX} is an even length
// string of hex characters 0 to f
#include "kernel/types.h"
#include "kernel/stat.h"
#include "user/user.h"

const char hex[] = "0123456789abcdef";

int main(int argc, char *argv[])
{
  for (int j = 0; j < strlen(argv[1]); j += 2)
  {
    char upper = (char)(strchr(hex, argv[1][j]) - hex);
    char lower = (char)(strchr(hex, argv[1][j + 1]) - hex);
    char byte = upper<<4;
    byte |= lower;
    write(1, &byte, 1);
  }
  write(1, "\n", 1);
  exit(0);
}
