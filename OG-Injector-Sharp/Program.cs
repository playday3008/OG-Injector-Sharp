using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace OGInjector
{
    class Program
    {
        [DllImport("coredll.dll", EntryPoint = "GetModuleHandleW", SetLastError = true)]
        public static extern IntPtr GetModuleHandle(string moduleName);

        [DllImport("kernel32", SetLastError = true, CharSet = CharSet.Ansi)]
        static extern IntPtr LoadLibrary([MarshalAs(UnmanagedType.LPStr)] string lpFileName);

        [DllImport("kernel32", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
        static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool WriteProcessMemory( IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int nSize, out IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, int dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out IntPtr lpThreadId);

        private static void Bypass(Process process)
        {
            IntPtr ntdll = LoadLibrary("ntdll");
            IntPtr ntOpenFile = GetProcAddress(ntdll, "NtOpenFile");
            byte[] originalBytes = new byte[5];
            Marshal.Copy(ntOpenFile, originalBytes, 0, 5);
            WriteProcessMemory(process.Handle, ntOpenFile, originalBytes, 5, out _);
        }

        static void Main(string[] _)
        {
            Console.Title = "OG Injector by PlayDay";
            string dllPath = Path.GetFullPath("library.dll");
            Process processes = Process.GetProcessesByName(Path.GetFileNameWithoutExtension("csgo.exe"))[0];
            Bypass(processes);
            IntPtr allocatedMem = VirtualAllocEx(processes.Handle, IntPtr.Zero, Encoding.Unicode.GetBytes(dllPath).Length + 1, 0x00002000 | 0x00001000, 0x04);
            WriteProcessMemory(processes.Handle, allocatedMem, Encoding.Unicode.GetBytes(dllPath), Encoding.Unicode.GetBytes(dllPath).Length + 1, out _);
            IntPtr kernel32 = GetModuleHandle("kernel32.dll");
            IntPtr loadLibraryAddr = GetProcAddress(kernel32, "LoadLibraryW");
            CreateRemoteThread(processes.Handle, IntPtr.Zero, 0, loadLibraryAddr, allocatedMem, 0, out _);
            return;
        }
    }
}
