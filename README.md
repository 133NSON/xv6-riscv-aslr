# xv6 ASLR Project
This project demonstrates a ret2libc attack and implements ASLR to mitigate this vulnerability

## Running xv6
It is unclear if this will run on Athena, but this is confirmed working on a local installation of the RISC-V toolchain on Ubuntu 18.04.

```bash
$ make qemu

[omitted output of compilation]
xv6 kernel is booting

virtio disk init 0
buf: 0x-7fff8000
hart 2 starting
hart 1 starting
exec /init: 
randomize_va_space = 1
buf: 0x-7fff8000
load offset: 0x1b0
argc: 1
init: starting sh
buf: 0x-7fff8000
exec sh: 
randomize_va_space = 1
buf: 0x-7fff8000
load offset: 0x2240
argc: 1
$
```
## ASLR Notes
When `exec` is called on an executable, the following is printed:
* `exec {name}`: a helpful debug message explaining the executable that is currently being loaded
* `randomize_va_space = 1`: if this flag is 1, then ASLR is enabled and memory addresses are randomized. If this is 0, then programs are loaded at a fixed offset of `0x0`
* `argc: 1`: this is the last statement of `exec` and tells the user how many arguments are being passed to the executable

You can change the flag by either changing the file on the host computer at `./randomize_va_space` in the project folder.
```bash
$ echo 0 > randomize_va_space
$ make clean && make qemu
```

You can also change the flag within xv6:
```bash
$ echo 0 > randomize_va_space
```

## Ret-2-libc demo
The generation of the attack file is performed using the `genExploit.py` file in the project root directory. In it, you will need to change the following variables:
* `a0_gadget_addr`: the address of the gadget that contains assembly instructions for a load from the memory at the stack pointer into `a0`
* `a0`: the value that the attacker wants `a0` to have after calling the gadget
* `system_addr`: the address of the first instruction in the `system` user function. `system(name)` is a wrapper around `exec` that will execute the file `name` with zero arguments.

You can generate the exploit file:
```bash
$ python2 genExploit.py
```
which will save the exploit into the file `exploit`. This is loaded into xv6 using the following:
```bash
$ make clean && make qemu
```
Running the exploit requires just one instruction:
```bash
$ overflow4 exploit
```

Notice that `user/overflow4.c` does not explicitly call `nsh` (which is denoted by an interactive shell that begins with `@` instead of `$`), but running the command above opens `nsh`. This indicates successful execution of the ret2libc attack.

Authors:
* Johnny Bui
* Neeraj Prasad