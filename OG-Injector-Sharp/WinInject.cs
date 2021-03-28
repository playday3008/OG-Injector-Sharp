using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

namespace OGInjector
{
    class WinInject
    {
        public static bool Inject(Process process, string processName, string libraryPath)
        {
            IntPtr allocatedMem = WinAPI.VirtualAllocEx(process.Handle, IntPtr.Zero, (uint)Encoding.Unicode.GetBytes(libraryPath).Length + 1, WinAPI.AllocationType.MEM_RESERVE | WinAPI.AllocationType.MEM_COMMIT, WinAPI.MemoryProtection.PAGE_READWRITE);
            if (allocatedMem == IntPtr.Zero)
            {
                Color.DarkRed(); Console.Write("Can't allocate memory in ");
                Color.Red(); Console.Write(processName);
                Color.DarkRed(); Console.WriteLine(" to write");
                Console.ResetColor();
                Console.WriteLine("Catched error code: " + Marshal.GetLastWin32Error());
                return false;
            }
            if (!WinAPI.WriteProcessMemory(process.Handle, allocatedMem, Encoding.Unicode.GetBytes(libraryPath), (uint)(uint)Encoding.Unicode.GetBytes(libraryPath).Length + 1, out _))
            {
                Color.DarkRed(); Console.Write("Can't write dll path to ");
                Color.Red(); Console.WriteLine(processName);
                Console.ResetColor();
                Console.WriteLine("Catched error code: " + Marshal.GetLastWin32Error());
                return false;
            }
            IntPtr kernel32 = WinAPI.GetModuleHandleW("kernel32.dll");
            if (kernel32 == IntPtr.Zero)
            {
                Color.DarkRed(); Console.Write("Can't get kernel32.dll handle");
                Console.ResetColor();
                Console.WriteLine("Catched error code: " + Marshal.GetLastWin32Error());
                return false;
            }
            IntPtr loadLibraryAddr = WinAPI.GetProcAddress(kernel32, "LoadLibraryW");
            if (loadLibraryAddr == IntPtr.Zero)
            {
                Color.DarkRed(); Console.Write("Can't get LoadLibraryW address from kernel32.dll");
                Console.ResetColor();
                Console.WriteLine("Catched error code: " + Marshal.GetLastWin32Error());
                return false;
            }
            IntPtr thread = WinAPI.CreateRemoteThread(process.Handle, IntPtr.Zero, 0, loadLibraryAddr, allocatedMem, 0, out _);
            if (thread == IntPtr.Zero)
            {
                Color.DarkRed(); Console.Write("Can't create remote thread with LoadLibrary module in ");
                Color.Red(); Console.WriteLine(processName);
                Console.ResetColor();
                Console.WriteLine("Catched error code: " + Marshal.GetLastWin32Error());
                return false;
            }
            return true;
        }
    }
}
