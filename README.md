# Perun's Fart
A C# application that unhooks AV and EDR to help run malicious code undetected. This differs to this [classic unhooking technique](https://github.com/plackyhacker/Unhook-BitDefender) because it does not need to load the 'clean' copy of **ntdll.dll** from disk, it copies it from another process before AV/EDR can hook it.

The concept is very similar, overwrite hooked syscalls with clean versions (unhooked).

# Introduction
This C# code is based upon one of the techniques demonstrated in the RED TEAM Operator: Windows Evasion Course from [Sektor7](https://institute.sektor7.net), the original, developed by Sektor7, is written in C/C++. I would recommend any of the malware development courses, there is a lot of great stuff to learn about creating malware in C/C++.

The blog entry can be found [here](https://blog.sektor7.net/#!res/2021/perunsfart.md). Apparently, **Fart** in Swedish translates to **speed** in English (this technique loads a new process in a suspended state, before AV/EDR can hook **ntdll.dll**), **fart** is also **luck** in Polish. A quick Google tells me that Perun is a Slavic God (this was confirmed in an email from Sektor7).

# Proof of Concept in x64dbg

The following image shows the `ZwCreateProcess` function when BitDefender is disabled:

![Disabled](https://github.com/plackyhacker/Peruns-Fart/blob/main/disabled.png?raw=true)

When I run the program again, but this time with BitDefender enabled, we can see that the `ZwCreateProcess` syscall in `ntdll.dll` is hooked, this is apparent by the `JMP` instruction:

![Enabled](https://github.com/plackyhacker/Peruns-Fart/blob/main/enabled.png?raw=true)

When Perun's Fart has completed unhooking `ntdll.dll` we can see that the syscall is back to normal (although the symbol is now `NtCreateProcess`):

![Unhooked](https://github.com/plackyhacker/Peruns-Fart/blob/main/unhooked.png?raw=true)

# Example
 
Execution of the code is shown below:

```
Creating a new process to read in a clean copy of NTDLL
[+] New process created. Pid: 6700
[+] Getting Module Size: ntdll
[+] Got Module base address: 0x7FFC92E00000
[+] Module is a valid image.
[+] e_lfanew equals 0xE0
[+] NT_HEADERS address is 0x7FFC92E000E0
[+] Module NT Headers is valid.
[+] ntdll Module Size: 2019328 bytes
[+] Bytes read from remote process memory: 2019328 bytes
[+] Killing process. Pid: 6700
[+] Done

Unhooking NTDLL
[+] Sections to enumerate is 9
[+] First section is .text
[+] First section is at 0x1E912279CA8
[+] Analysing section .text
[+] .text section is at 0x1E912279CA8
[+] First syscall found at offset: 0x9F9E0, addr: 0x7FFC92E9F9E0
[+] Last syscall found at offset: 0xA33C8, addr: 0x7FFC92EA33C8
[+] VirtualProtect Dll to PAGE_EXECUTE_READWRITE...
[+] Unhooking Dll by copying clean data...
[+] VirtualProtect Dll to OldProtect
[+] Done
```

I have not injected any shellcode in the PoC. The technique achieves the same result as [this technique](https://github.com/plackyhacker/Unhook-BitDefender), see notes below for BitDefender specifics.

# Notes

The code can be changed to unhook any loaded DLL. BitDefender hooks **ntdll.dll** and **kernelbase.dll**. If I get time I might update the code to unhook both of these, at the moment the PoC only unhooks **ntdll.dll**.
