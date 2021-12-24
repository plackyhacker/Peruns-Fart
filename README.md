# Perun's Fart
A C# application that unhooks AV and EDR to help run malicious code undetected.

# Introduction
This C# code is based upon one of the techniques demonstrated in the RED TEAM Operator: Windows Evasion Course from [Sektor7](https://institute.sektor7.net), the original is written in C/C++. I would recommend any of the malware development courses, there is a lot of great stuff to learn about creating malware in C/C++.

The blog entry can be found [here](https://blog.sektor7.net/#!res/2021/perunsfart.md). Apparently, Fart in Swedish means speed (this technique loads a new process in a suspended state, before AV/EDR can hook **ntdll.dll**). I have no idea who or what Perun is, although a quick Google tells me that Perun is a Slavic God.
