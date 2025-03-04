# Buffer-Overflow-Attack-Sim

## Objective:

This project demonstrates a buffer overflow exploit on a vulnerable C program running in a SEED Ubuntu virtual machine. The goal is to overwrite the return address and execute arbitrary code to gain root access.

## Vulnerable Program & Python Exploit:

lab3stack.c  
The main function reads input from badfile, storing up to 517 bytes in the str array, and passes it to the bof() function. Inside bof(), this input is copied into a fixed-size buffer of 77 bytes using strcpy() without any bounds checking. Since strcpy() does not verify the length of the input, an attacker can craft a malicious badfile with more than 77 bytes, causing a buffer overflow that overwrites adjacent memory, including the function’s return address. Additionally, the program does not validate the contents of “badfile”, allowing arbitrary data (including shellcode) to be injected. If successfully exploited, this vulnerability enables an attacker to redirect execution.  
![](https://github.com/cade-rob99/images/blob/main/image1.png)  
lab3exploit.py.py  
The Python exploit script generates a malicious payload “badfile” designed to trigger a buffer overflow in the vulnerable C program. It first creates a 517-byte buffer filled with NOPs (0x90), ensuring safe execution if the return address lands anywhere within it. The script then appends shellcode at the end of this buffer, which, when executed, spawns a shell (/bin/sh) with root privileges. The offset (0x59 or 89 bytes) is used to correctly position the overwritten return address, which is replaced with a controlled memory address (0xBFFFEAC0) that points into the NOP sled, ultimately leading execution to the shellcode. This payload is then written to “badfile”, which, when processed by the vulnerable program, causes an uncontrolled overwrite of the return address, redirecting execution to the injected shellcode.  
![](https://github.com/cade-rob99/images/blob/main/image2.png)

## Attack Process:

### Step 1:

The vulnerable program, along with the python exploit, was created and stored in the home directory of the SEED user account to set up the testing environment.  
![](https://github.com/cade-rob99/images/blob/main/image3.png)

### Step 2:

Address Space Layout Randomization (ASLR) is a security mechanism that randomizes memory addresses to make it harder for attackers to predict function locations and exploit buffer overflow vulnerabilities. For the purpose of this demonstration, ASLR will be disabled to ensure consistent memory addresses during the attack simulation.  
 ![](https://github.com/cade-rob99/images/blob/main/image4.png)

### Step 3:

An empty output file (badfile) is created as a placeholder to store the crafted payload before it is injected into the vulnerable program.  
![](https://github.com/cade-rob99/images/blob/main/image5.png)

### Step 4:

The file “lab3stack.c” is compiled into an executable named “lab3stack\_dbg” with debugging symbols included, stack protection disabled, and the stack marked as executable. These modifications allow shellcode to be injected into the stack and executed, bypassing security mechanisms that normally prevent such attacks.  
![](https://github.com/cade-rob99/images/blob/main/image6.png)

### Step 5:

The GNU Debugger (GDB) is launched, and a breakpoint is set at the bof function to pause execution when the function is reached. Once the program is executed (run), it halts at the breakpoint, allowing for memory analysis. The base pointer (EBP) and buffer address are printed to determine the exact offset needed to overwrite the return address.  
![](https://github.com/cade-rob99/images/blob/main/image7.png)  
![](https://github.com/cade-rob99/images/blob/main/image8.png)

### Step 6:

The offset value and return address obtained in the previous step were placed into the Python exploit script. The return address was calculated by adding 120 bytes to the EBP value, as the return address is typically stored at EBP \+ 120 on the stack. Additionally, offset \+ 4 bytes in hexadecimal was added in the script to correctly overwrite the saved return address, accounting for the fact that the return address is stored 4 bytes after EBP in a standard stack frame. These calculations ensure that execution is redirected as intended when the buffer overflow occurs.  
![](https://github.com/cade-rob99/images/blob/main/image9.png)

### Step 7:

The exploit script is first given full execution permissions to ensure it can generate the malicious payload, which is then written to badfile. The vulnerable program is assigned root ownership and given Set-UID, allowing it to execute with root privileges when run by any user. When the program processes badfile, the buffer overflow overwrites the return address, redirecting execution to the injected shellcode that spawns a shell. To ensure an unrestricted shell, a symbolic link replaces /bin/sh with /bin/zsh, preventing the system from defaulting to a restricted shell like dash.  
![](https://github.com/cade-rob99/images/blob/main/image10.png)

### Step 8:

The vulnerable program is executed, successfully triggering the buffer overflow. As a result, the injected shellcode runs with root privileges, granting full control over the system and allowing unrestricted command execution.  
![](https://github.com/cade-rob99/images/blob/main/image11.png)
