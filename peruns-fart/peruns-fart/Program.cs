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
                Debug("[+] New process created. Pid:{0}", new string[] { pi.dwProcessId.ToString() });






                // kill the spawned process
                Debug("[+] Killing process. Pid:{0}", new string[] { pi.dwProcessId.ToString() });
                Process.GetProcessById(pi.dwProcessId).Kill();
            }






            
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
