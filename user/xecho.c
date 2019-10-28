// user program to echo hex code, useful for breaking things

// call by running `xecho {HEX}`, where {HEX} is an even length
// string of hex characters 0 to f
#include "kernel/types.h"
#include "kernel/stat.h"
#include "user/user.h"

const char hex[] = "0123456789abcdef";

int main(int argc, char *argv[])
{
  char* input;

  if (argc == 1) {
    // no arguments were provided, read from stdin
    char buffer[1000];
    memset(buffer, 0, 1000);
    input = buffer;
    gets(buffer, 1000);
    // replace newline character
  } else {
    input = argv[1];
  }
  for (int j = 0; j < strlen(input); j += 2)
  {
    char* upper = strchr(hex, input[j]);
    if (!upper) break; // break if input is int valid hex
    char* lower = strchr(hex, input[j + 1]);
    if (!lower) break; // break if input is not valid hex

    // since strchr returns pointer, subtract from base pointer to find index
    char upperBits = (char) (upper - hex) << 4;
    char lowerBits = (char) (lower - hex);

    char byte = upperBits | lowerBits;
    write(1, &byte, 1);
  }
  write(1, "\n", 1);
  exit(0);
}
