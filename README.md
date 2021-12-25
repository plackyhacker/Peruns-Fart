# Perun's Fart
A C# application that unhooks AV and EDR to help run malicious code undetected. This differs to this [classic unhooking technique](https://github.com/plackyhacker/Unhook-BitDefender) because it does not need to load the 'clean' copy of **ntdll.dll** from disk, it copies it from another process before AV/EDR can hook it.

# Introduction
This C# code is based upon one of the techniques demonstrated in the RED TEAM Operator: Windows Evasion Course from [Sektor7](https://institute.sektor7.net), the original, developed by Sektor7, is written in C/C++. I would recommend any of the malware development courses, there is a lot of great stuff to learn about creating malware in C/C++.

The blog entry can be found [here](https://blog.sektor7.net/#!res/2021/perunsfart.md). Apparently, **Fart** in Swedish translates to **speed** in English (this technique loads a new process in a suspended state, before AV/EDR can hook **ntdll.dll**), **fart** is also **luck** in Polish. A quick Google tells me that Perun is a Slavic God.

I am still unsure of the exact meaning of the name, Perun's Luck or Perun's Speed.
