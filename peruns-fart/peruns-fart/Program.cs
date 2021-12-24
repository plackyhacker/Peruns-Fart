using System;
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
                UnhookDLL(cache);
                Debug("[+] Done");
            }
        }

        static bool UnhookDLL(byte[] cleanModule)
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
                }
            }

            return true;
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
