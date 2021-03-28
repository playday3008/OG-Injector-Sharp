using System;
using System.Runtime.InteropServices;

namespace OGInjector
{
    class WinAPI
    {
        [Flags]
        public enum AllocationType : uint
        {
            MEM_UNMAP_WITH_TRANSIENT_BOOST = 0x00000001,
            MEM_COALESCE_PLACEHOLDERS = MEM_UNMAP_WITH_TRANSIENT_BOOST,
            MEM_PRESERVE_PLACEHOLDER = 0x00000002,
            MEM_COMMIT = 0x00001000,
            MEM_RESERVE = 0x00002000,
            MEM_REPLACE_PLACEHOLDER = 0x00004000,
            MEM_DECOMMIT = MEM_REPLACE_PLACEHOLDER,
            MEM_RELEASE = 0x00008000,
            MEM_FREE = 0x00010000,
            MEM_PRIVATE = 0x00020000,
            MEM_RESERVE_PLACEHOLDER = 0x00040000,
            MEM_MAPPED = MEM_RESERVE_PLACEHOLDER,
            MEM_RESET = 0x00080000,
            MEM_TOP_DOWN = 0x00100000,
            MEM_WRITE_WATCH = 0x00200000,
            MEM_PHYSICAL = 0x00400000,
            MEM_ROTATE = 0x00800000,
            MEM_DIFFERENT_IMAGE_BASE_OK = MEM_ROTATE,
            MEM_IMAGE = 0x01000000,
            MEM_RESET_UNDO = MEM_IMAGE,
            MEM_LARGE_PAGES = 0x20000000,
            MEM_4MB_PAGES = 0x80000000,
            MEM_64K_PAGES = MEM_LARGE_PAGES | MEM_PHYSICAL
        }

        [Flags]
        public enum MemoryProtection : uint
        {
            PAGE_NOACCESS = 0x01,
            PAGE_READONLY = 0x02,
            PAGE_READWRITE = 0x04,
            PAGE_WRITECOPY = 0x08,
            PAGE_EXECUTE = 0x10,
            PAGE_EXECUTE_READ = 0x20,
            PAGE_EXECUTE_READWRITE = 0x40,
            PAGE_EXECUTE_WRITECOPY = 0x80,
            PAGE_GUARD = 0x100,
            PAGE_NOCACHE = 0x200,
            PAGE_WRITECOMBINE = 0x400,
            PAGE_GRAPHICS_NOACCESS = 0x0800,
            PAGE_GRAPHICS_READONLY = 0x1000,
            PAGE_GRAPHICS_READWRITE = 0x2000,
            PAGE_GRAPHICS_EXECUTE = 0x4000,
            PAGE_GRAPHICS_EXECUTE_READ = 0x8000,
            PAGE_GRAPHICS_EXECUTE_READWRITE = 0x10000,
            PAGE_GRAPHICS_COHERENT = 0x20000,
            PAGE_GRAPHICS_NOCACHE = 0x40000,
            PAGE_ENCLAVE_THREAD_CONTROL = 0x80000000,
            PAGE_REVERT_TO_FILE_MAP = PAGE_ENCLAVE_THREAD_CONTROL,
            PAGE_TARGETS_NO_UPDATE = 0x40000000,
            PAGE_TARGETS_INVALID = PAGE_TARGETS_NO_UPDATE,
            PAGE_ENCLAVE_UNVALIDATED = 0x20000000,
            PAGE_ENCLAVE_MASK = 0x10000000,
            PAGE_ENCLAVE_DECOMMIT = PAGE_ENCLAVE_MASK,
            PAGE_ENCLAVE_SS_FIRST = PAGE_ENCLAVE_MASK | 1,
            PAGE_ENCLAVE_SS_REST = PAGE_ENCLAVE_MASK | 2
        }

        [DllImport("kernel32.dll", BestFitMapping = true, CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Unicode, EntryPoint = "GetModuleHandleW", ExactSpelling = true, PreserveSig = true, SetLastError = true, ThrowOnUnmappableChar = true)]
        public static extern IntPtr GetModuleHandleW(
            [In, Optional, MarshalAs(UnmanagedType.LPWStr)]
            string lpModuleName);

        [DllImport("kernel32", BestFitMapping = true, CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Unicode, EntryPoint = "LoadLibraryW", ExactSpelling = true, PreserveSig = true, SetLastError = true, ThrowOnUnmappableChar = true)]
        public static extern IntPtr LoadLibraryW(
            [In, MarshalAs(UnmanagedType.LPWStr)]
            string lpLibFileName);

        [DllImport("kernel32", BestFitMapping = true, CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Ansi, EntryPoint = "GetProcAddress", ExactSpelling = true, PreserveSig = true, SetLastError = true, ThrowOnUnmappableChar = true)]
        public static extern IntPtr GetProcAddress(
            [In]
            IntPtr hModule,
        #pragma warning disable CA2101 // Укажите маршалинг для строковых аргументов P/Invoke
            [In, MarshalAs(UnmanagedType.LPStr)]
        #pragma warning restore CA2101 // Укажите маршалинг для строковых аргументов P/Invoke
            string lpProcName);

        [DllImport("kernel32.dll", BestFitMapping = true, CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Ansi, EntryPoint = "WriteProcessMemory", ExactSpelling = true, PreserveSig = true, SetLastError = true, ThrowOnUnmappableChar = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool WriteProcessMemory(
            [In]
            IntPtr hProcess,
            [In]
            IntPtr lpBaseAddress,
            [In, MarshalAs(UnmanagedType.LPArray)]
            byte[] lpBuffer,
            [In, MarshalAs(UnmanagedType.U4)]
            uint nSize,
            [Out, Optional, MarshalAs(UnmanagedType.U4)]
            out uint lpNumberOfBytesWritten);

        [DllImport("kernel32.dll", BestFitMapping = true, CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Ansi, EntryPoint = "VirtualAllocEx", ExactSpelling = true, PreserveSig = true, SetLastError = true, ThrowOnUnmappableChar = true)]
        public static extern IntPtr VirtualAllocEx(
            [In]
            IntPtr hProcess,
            [In, Optional]
            IntPtr lpAddress,
            [In, MarshalAs(UnmanagedType.U4)]
            uint dwSize,
            [In, MarshalAs(UnmanagedType.U4)]
            AllocationType flAllocationType,
            [In, MarshalAs(UnmanagedType.U4)]
            MemoryProtection flProtect);

        [DllImport("kernel32.dll", BestFitMapping = true, CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Ansi, EntryPoint = "CreateRemoteThread", ExactSpelling = true, PreserveSig = true, SetLastError = true, ThrowOnUnmappableChar = true)]
        public static extern IntPtr CreateRemoteThread(
            [In]
            IntPtr hProcess,
            [In, Optional]
            IntPtr lpThreadAttributes,
            [In, MarshalAs(UnmanagedType.U4)]
            uint dwStackSize,
            [In]
            IntPtr lpStartAddress,
            [In, Optional]
            IntPtr lpParameter,
            [In, MarshalAs(UnmanagedType.U4)]
            uint dwCreationFlags,
            [Out, Optional, MarshalAs(UnmanagedType.U4)]
            out uint lpThreadId);
    }
}
