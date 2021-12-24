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
            STARTUPINFO si = new STARTUPINFO();
            PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
            SECURITY_ATTRIBUTES pAttr = new SECURITY_ATTRIBUTES();
            SECURITY_ATTRIBUTES tAttr = new SECURITY_ATTRIBUTES();

            bool success = CreateProcess(null, "cmd.exe", ref pAttr, ref tAttr, false, CreateProcessFlags.CREATE_NEW_CONSOLE | CreateProcessFlags.CREATE_SUSPENDED, IntPtr.Zero, "C:\\Windows\\System32\\", ref si, out pi);

            if(success)
            {
                Debug("[+] New process created. Pid: {0}", new string[] { pi.dwProcessId.ToString() });

                uint modSize = GetModuleSize("ntdll");

                if (modSize == 0)
                {
                    Debug("[!] Getting NTDLL Module Size failed!");
                }
                else
                {
                    Debug("[!] ntdll Module Size: {0}", new string[] { modSize.ToString() });
                }

                // kill the spawned process
                Debug("[+] Killing process. Pid: {0}", new string[] { pi.dwProcessId.ToString() });
                Process.GetProcessById(pi.dwProcessId).Kill();
            }
            else
            {
                Debug("[!] Unable to create a new process!");
            }
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


            // Marshall a pointer into an IMAGE_DOS_HEADER struct
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
