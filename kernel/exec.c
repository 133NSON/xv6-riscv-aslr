#include "types.h"
#include "param.h"
#include "memlayout.h"
#include "riscv.h"
#include "spinlock.h"
#include "proc.h"
#include "defs.h"
#include "elf.h"

uint64 random(int, int);

static int loadseg(pde_t *pgdir, uint64 addr, struct inode *ip, uint offset, uint sz);

int readsh(struct secthdr*, struct inode*, int);

int
exec(char *path, char **argv)
{
  printf("exec %s: ", path);
  char *s, *last;
  int i, off;
  uint64 argc, sz, sp, ustack[MAXARG+1], stackbase;
  struct elfhdr elf;
  struct inode *ip;
  struct proghdr ph;
  struct secthdr sh;
  pagetable_t pagetable = 0, oldpagetable;
  struct proc *p = myproc();
  uint64 instr;

  begin_op(ROOTDEV);

  if((ip = namei(path)) == 0){
    end_op(ROOTDEV);
    return -1;
  }
  ilock(ip);

  // Check ELF header
  if(readi(ip, 0, (uint64)&elf, 0, sizeof(elf)) != sizeof(elf))
    goto bad;
  if(elf.magic != ELF_MAGIC)
    goto bad;

  // print elf type
  if(elf.type == 2)
    printf("loading executable elf...\n");
  if(elf.type == 3)
    printf("loading dynamic elf\n");

  if((pagetable = proc_pagetable(p)) == 0)
    goto bad;

  sz = 0;

  // Get symbol table
  struct elfsym symbol;
  uint64 symboladdrs[100] = {0};
  uint currentsymbol = 0;
  for(i=0, off=elf.shoff; i<elf.shnum; i++, off += elf.shentsize) {
    if (readi(ip, 0, (uint64)&sh, off, elf.shentsize) != elf.shentsize) {
      printf("exec: section readi error on section %d\n", i);
      goto bad;
    }
    int not_dynsym = (sh.type ^ ELF_SECT_TYPE_DYNSYM);
    if (!not_dynsym) {
      // found section header for dynamic symbol table
      // read through each dynamic symbol
      for (int sectoff = 0; sectoff < sh.size; sectoff += sh.entsize) {
        int size = readi(
          ip,
          0,
          (uint64)&symbol,
          sh.offset + sectoff,
          sh.entsize);
        // printf(
        //   "sym a:0x%x, b: 0x%x, c: 0x%x\n",
        //   symbol.a,
        //   symbol.addr,
        //   symbol.c);
        symboladdrs[currentsymbol++] = symbol.addr;
        if (size != sizeof(struct elfrel))
          goto bad;
      }
    }
  }

  // Load program into memory.
  uint64 load_offset = 0 * PGSIZE; // must be multiple of PGSIZE
  printf("load offset: 0x%x\n", load_offset);

  uvmalloc(pagetable, 0, load_offset);
  for(i=0, off=elf.phoff; i<elf.phnum; i++, off+=sizeof(ph)){
    if(readi(ip, 0, (uint64)&ph, off, sizeof(ph)) != sizeof(ph)) {
      printf("exec: readi error\n");
      goto bad;
    }
    // ph.vaddr = PGROUNDDOWN(ph.vaddr); // round up vaddr
    if(ph.type != ELF_PROG_LOAD)
      continue;
    if(ph.memsz < ph.filesz) {
      printf("exec: memsz smaller than filesz error\n");
      goto bad;
    }
    if((sz = uvmalloc(pagetable, sz + load_offset, ph.vaddr + ph.memsz + load_offset)) == 0) {
      printf("exec: uvmalloc error\n");
      goto bad;
    }
    printf("loading offset 0x%x into vaddr: 0x%x\n", ph.off, ph.vaddr);
    if(loadseg(pagetable, ph.vaddr + load_offset, ip, ph.off, ph.filesz) < 0) {
      printf("exec: loadseg error\n");
      goto bad;
    }
  }
  sz += load_offset;

  struct elfrel relocation;
  // Get Section Headers
  for(i=0, off=elf.shoff; i<elf.shnum; i++, off += elf.shentsize) {
    if (readi(ip, 0, (uint64)&sh, off, elf.shentsize) != elf.shentsize) {
      printf("exec: section readi error on section %d\n", i);
      goto bad;
    }
    int not_rela = (sh.type ^ ELF_SECT_TYPE_RELA);
    if (!not_rela) {
      // found section header for relocations
      // read through each relocation
      for (int sectoff = 0; sectoff < sh.size; sectoff += sh.entsize) {
        int size = readi(
          ip,
          0,
          (uint64)&relocation,
          sh.offset + sectoff,
          sh.entsize);
        printf(
          "reloc offset:0x%x, type: 0x%x, symbol: %d, addr: 0x%x\n",
          relocation.r_offset,
          ELF64_R_TYPE(relocation.r_info),
          ELF64_R_SYM(relocation.r_info),
          symboladdrs[ELF64_R_SYM(relocation.r_info)]);
        switch (ELF64_R_TYPE(relocation.r_info)) {
          case R_RISCV_RELATIVE:
            printf("relative\n");
            // get instruction from memory
            if (copyin(pagetable, (char*)&instr, (uint64)relocation.r_offset, 8) != 0)
              panic("exec: copyin1 relocation");
            printf("read: 0x%x\n", instr);
            instr = 0x0;
            if (copyout(pagetable, (uint64)relocation.r_offset, (char*)&instr, 8) != 0)
              panic("exec: copyout1 relocation");
            printf("write: 0x%x\n", instr);
            break;
          case R_RISCV_JUMP_SLOT:
            printf("jump slot\n");
            // get instruction from memory
            instr = 0;
            if (copyin(pagetable, (char*)&instr, (uint64)relocation.r_offset, 8) != 0)
              panic("exec: copyin2 relocation");
            printf("read: 0x%x\n", instr);
            instr = symboladdrs[ELF64_R_SYM(relocation.r_info)];
            if (copyout(pagetable, (uint64)relocation.r_offset, (char*)&instr, 8) != 0)
              panic("exec: copyout2 relocation");
            printf("write: 0x%x\n", instr);
            break;
        }
        if (size != sizeof(struct elfrel))
          goto bad;
      }
    }
  }
  iunlockput(ip);
  end_op(ROOTDEV);
  ip = 0;

  p = myproc();
  uint64 oldsz = p->sz;

  // Allocate random number of pages at the next page boundary.
  // Use the last one as the user stack.
  sz = PGROUNDUP(sz);
  if((sz = uvmalloc(pagetable, sz, sz + 2*PGSIZE)) == 0)
    goto bad;
  uvmclear(pagetable, sz-2*PGSIZE);
  sp = sz;
  stackbase = sp - PGSIZE;

  // Push argument strings, prepare rest of stack in ustack.
  for(argc = 0; argv[argc]; argc++) {
    if(argc >= MAXARG)
      goto bad;
    sp -= strlen(argv[argc]) + 1;
    sp -= sp % 16; // riscv sp must be 16-byte aligned
    if(sp < stackbase)
      goto bad;
    if(copyout(pagetable, sp, argv[argc], strlen(argv[argc]) + 1) < 0)
      goto bad;
    ustack[argc] = sp;
  }
  ustack[argc] = 0;

  // push the array of argv[] pointers.
  sp -= (argc+1) * sizeof(uint64);
  sp -= sp % 16;
  if(sp < stackbase)
    goto bad;
  if(copyout(pagetable, sp, (char *)ustack, (argc+1)*sizeof(uint64)) < 0)
    goto bad;

  // arguments to user main(argc, argv)
  // argc is returned via the system call return
  // value, which goes in a0.
  p->tf->a1 = sp;

  // Save program name for debugging.
  for(last=s=path; *s; s++)
    if(*s == '/')
      last = s+1;
  safestrcpy(p->name, last, sizeof(p->name));
    
  // Commit to the user image.
  oldpagetable = p->pagetable;
  p->pagetable = pagetable;
  p->sz = sz;
  p->tf->epc = elf.entry + load_offset;  // initial program counter = main
  p->tf->sp = sp; // initial stack pointer
  proc_freepagetable(oldpagetable, oldsz);
  printf("argc: %d\n", argc);
  return argc; // this ends up in a0, the first argument to main(argc, argv)

 bad:
  if(pagetable)
    proc_freepagetable(pagetable, sz);
  if(ip){
    iunlockput(ip);
    end_op(ROOTDEV);
  }
  return -1;
}

// Load a program segment into pagetable at virtual address va.
// va must be page-aligned
// and the pages from va to va+sz must already be mapped.
// Returns 0 on success, -1 on failure.
static int
loadseg(pagetable_t pagetable, uint64 va, struct inode *ip, uint offset, uint sz)
{
  uint i, n;
  uint64 pa;

  uint64 pg_offset = va - PGROUNDDOWN(va);

  // manually fill the first page, which might not be page aligned
  pa = walkaddr(pagetable, PGROUNDDOWN(va));
  if (pa == 0)
    panic("loadseg: address should exist");
  n = (sz < PGSIZE)? sz : PGSIZE;
  if(readi(ip, 0, (uint64)pa + pg_offset, offset, n) != n)
    return -1;

  // use for loop for subsequent pages
  for(i = PGSIZE; i < sz; i += PGSIZE){
    pa = walkaddr(pagetable, PGROUNDDOWN(va) + i);
    if(pa == 0)
      panic("loadseg: address should exist");
    if(sz - i < PGSIZE)
      n = sz - i;
    else
      n = PGSIZE;
    if(readi(ip, 0, (uint64)pa, offset-pg_offset+i, n) != n)
      return -1;
  }
  
  return 0;
}
