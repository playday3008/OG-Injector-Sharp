using System;
using System.Diagnostics;
using System.IO;
using System.Threading;
using System.Runtime.Intrinsics.X86;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using System.Text;

//#define OSIRIS
//#define GOESP
//#define BETA

namespace OG_Injector_Sharp
{
	class WinAPI
	{
		[Flags]
		public enum AllocationType : uint
		{
			MEM_UNMAP_WITH_TRANSIENT_BOOST = 0x00000001,
			MEM_COALESCE_PLACEHOLDERS = 0x00000001,
			MEM_PRESERVE_PLACEHOLDER = 0x00000002,
			MEM_COMMIT = 0x00001000,
			MEM_RESERVE = 0x00002000,
			MEM_REPLACE_PLACEHOLDER = 0x00004000,
			MEM_DECOMMIT = 0x00004000,
			MEM_RELEASE = 0x00008000,
			MEM_FREE = 0x00010000,
			MEM_PRIVATE = 0x00020000,
			MEM_RESERVE_PLACEHOLDER = 0x00040000,
			MEM_MAPPED = 0x00040000,
			MEM_RESET = 0x00080000,
			MEM_TOP_DOWN = 0x00100000,
			MEM_WRITE_WATCH = 0x00200000,
			MEM_PHYSICAL = 0x00400000,
			MEM_ROTATE = 0x00800000,
			MEM_DIFFERENT_IMAGE_BASE_OK = 0x00800000,
			MEM_IMAGE = 0x01000000,
			MEM_RESET_UNDO = 0x01000000,
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
			PAGE_REVERT_TO_FILE_MAP = 0x80000000,
			PAGE_TARGETS_NO_UPDATE = 0x40000000,
			PAGE_TARGETS_INVALID = 0x40000000,
			PAGE_ENCLAVE_UNVALIDATED = 0x20000000,
			PAGE_ENCLAVE_MASK = 0x10000000,
			PAGE_ENCLAVE_DECOMMIT = PAGE_ENCLAVE_MASK | 0,
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
			[In, MarshalAs(UnmanagedType.LPStr)]
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

	class Program
	{
		static bool Bypass(Process process, string processName)
		{
			IntPtr ntdll = WinAPI.LoadLibraryW("ntdll");
			if (ntdll == IntPtr.Zero)
			{
				Console.ForegroundColor = ConsoleColor.DarkRed;
				Console.WriteLine("Can't load ntdll.dll module");
				Console.ResetColor();
				Console.WriteLine("Catched error code: " + Marshal.GetLastWin32Error());
				return false;
			}
			IntPtr ntOpenFile = WinAPI.GetProcAddress(ntdll, "NtOpenFile");
			if (ntOpenFile != IntPtr.Zero)
			{
				byte[] originalBytes = new byte[5];
				Marshal.Copy(ntOpenFile, originalBytes, 0, 5);
                if (!WinAPI.WriteProcessMemory(process.Handle, ntOpenFile, originalBytes, 5, out _))
				{
					Console.ForegroundColor = ConsoleColor.DarkRed;
					Console.WriteLine("Can't write original NtOpenFile bytes to ");
					Console.ForegroundColor = ConsoleColor.Red;
					Console.WriteLine(processName);
					Console.ResetColor();
					Console.WriteLine("Catched error code: " + Marshal.GetLastWin32Error());
					return false;
				}
				return true;
			}
			else
			{
				Console.ForegroundColor = ConsoleColor.DarkRed;
				Console.WriteLine("Can't find NtOpenFile into ntdll.dll");
				Console.ResetColor();
				Console.WriteLine("Catched error code: " + Marshal.GetLastWin32Error());
				return false;
			}
		}

		static int Main(string[] args)
		{
			Console.OutputEncoding = Encoding.Unicode;
			Console.ForegroundColor = ConsoleColor.Red;		Console.WriteLine(@"   ____  ______   ____        _           __            "); Thread.Sleep(50);
			Console.ForegroundColor = ConsoleColor.Green;	Console.WriteLine(@"  / __ \/ ____/  /  _/___    (_)__  _____/ /_____  _____"); Thread.Sleep(50);
			Console.ForegroundColor = ConsoleColor.Yellow;	Console.WriteLine(@" / / / / / __    / // __ \  / / _ \/ ___/ __/ __ \/ ___/"); Thread.Sleep(50);
			Console.ForegroundColor = ConsoleColor.Blue;	Console.WriteLine(@"/ /_/ / /_/ /  _/ // / / / / /  __/ /__/ /_/ /_/ / /    "); Thread.Sleep(50);
			Console.ForegroundColor = ConsoleColor.Magenta;	Console.WriteLine(@"\____/\____/  /___/_/ /_/_/ /\___/\___/\__/\____/_/     "); Thread.Sleep(50);
			Console.ForegroundColor = ConsoleColor.Cyan;	Console.WriteLine(@"    ____  __           /___/                   __ __    "); Thread.Sleep(50);
			Console.ForegroundColor = ConsoleColor.Red;		Console.WriteLine(@"   / __ \/ /___ ___  __/ __ \____ ___  __   __/ // /_   "); Thread.Sleep(50);
			Console.ForegroundColor = ConsoleColor.Green;	Console.WriteLine(@"  / /_/ / / __ `/ / / / / / / __ `/ / / /  /_  _  __/   "); Thread.Sleep(50);
			Console.ForegroundColor = ConsoleColor.Yellow;	Console.WriteLine(@" / ____/ / /_/ / /_/ / /_/ / /_/ / /_/ /  /_  _  __/    "); Thread.Sleep(50);
			Console.ForegroundColor = ConsoleColor.Blue;	Console.WriteLine(@"/_/   /_/\__,_/\__, /_____/\__,_/\__, /    /_//_/       "); Thread.Sleep(50);
			Console.ForegroundColor = ConsoleColor.Magenta;	Console.WriteLine(@"              /____/            /____/                  "); Thread.Sleep(50);
			Console.ResetColor();

		#if OSIRIS
			string dllname = "Osiris";
		#elif GOESP
			string dllname = "GOESP";
		#else
			string dllname = "library.dll";
#endif

#if (OSIRIS || GOESP) && BETA
			dllname += "_BETA";
#endif

#if OSIRIS || GOESP
			if (Avx2.IsSupported)
				dllname += "_AVX2.dll";
			else if (Avx.IsSupported)
				dllname += "_AVX.dll";
			else if (Sse2.IsSupported)
				dllname += "_SSE2.dll";
			else
			{
				Console.ForegroundColor = ConsoleColor.DarkRed;
				Console.WriteLine("Unsupported CPU intrinsics!");
				Console.ForegroundColor = ConsoleColor.White;
				Console.WriteLine("Press any key to continue...");
				Console.ResetColor();
				Console.ReadKey();
				return 1;
			}
#endif

			if (File.Exists(dllname))
			{
				Console.ForegroundColor = ConsoleColor.DarkGreen;
				Console.Write("DLL: ");
				Console.ForegroundColor = ConsoleColor.Green;
				Console.Write(dllname);
				Console.ForegroundColor = ConsoleColor.DarkGreen;
				Console.WriteLine(" found");
				Console.ResetColor();
			}
			else
			{
				Console.ForegroundColor = ConsoleColor.DarkRed;
				Console.Write("Can't find: ");
				Console.ForegroundColor = ConsoleColor.Red;
				Console.WriteLine(dllname);
				Console.ForegroundColor = ConsoleColor.White;
				Console.WriteLine("Press any key to continue...");
				Console.ResetColor();
				Console.ReadKey();
				return 1;
			}

			string processName = "csgo.exe";

			Console.ForegroundColor = ConsoleColor.DarkYellow;
			Console.Write("Finding ");
			Console.ForegroundColor = ConsoleColor.Red;
			Console.Write(processName);
			Console.ForegroundColor = ConsoleColor.DarkYellow;
			Console.WriteLine(" process");
			Console.ResetColor();

			Process[] processes = Process.GetProcessesByName(Path.GetFileNameWithoutExtension(processName));

			if (processes.Length == 0)
			{
				Console.ForegroundColor = ConsoleColor.DarkRed;
				Console.Write("Can't find: ");
				Console.ForegroundColor = ConsoleColor.Red;
				Console.WriteLine(processName);
				Console.ForegroundColor = ConsoleColor.White;
				Console.WriteLine("Press any key to continue...");
				Console.ResetColor();
				Console.ReadKey();
				return 1;
			}
			else if (processes.Length > 1)
			{
				Console.ForegroundColor = ConsoleColor.DarkGreen;
				Console.Write("Process: ");
				Console.ForegroundColor = ConsoleColor.Green;
				Console.Write(processName);
				Console.ForegroundColor = ConsoleColor.DarkGreen;
				Console.Write(" found with PID's:");
				int pcounter = 0;
				foreach (Process p in processes)
				{
					pcounter++;
					Console.ForegroundColor = (ConsoleColor)(((pcounter - 1) % 6) + 9);
					Console.Write(" {0}", p.Id);
					if (pcounter != processes.Length)
					{
						Console.ForegroundColor = (ConsoleColor)(((pcounter - 1) % 6) + 9);
						Console.Write(',');
					}
					else
						Console.WriteLine(';');
				}
				Console.ForegroundColor = ConsoleColor.DarkYellow;
				Console.Write("Used the latest PID available in the list above: ");
				Console.ForegroundColor = ConsoleColor.Yellow;
				Console.WriteLine(processes[^1].Id);
				Console.ResetColor();
			}
			else
			{
				Console.ForegroundColor = ConsoleColor.DarkGreen;
				Console.Write("Process: ");
				Console.ForegroundColor = ConsoleColor.Green;
				Console.Write(processName);
				Console.ForegroundColor = ConsoleColor.DarkGreen;
				Console.Write(" found with PID: ");
				Console.ForegroundColor = ConsoleColor.Green;
				Console.WriteLine(processes[^1].Id);
				Console.ResetColor();
			}

			if (!Bypass(processes[^1], processName))
				return 1;

			string dllPath = Path.GetFullPath(dllname);

			Console.ForegroundColor = ConsoleColor.DarkYellow;
			Console.Write("Injecting ");
			Console.ForegroundColor = ConsoleColor.Yellow;
			Console.Write(dllname);
			Console.ForegroundColor = ConsoleColor.DarkYellow;
			Console.Write(" into ");
			Console.ForegroundColor = ConsoleColor.Green;
			Console.Write(processName);
			Console.ForegroundColor = ConsoleColor.DarkYellow;
			Console.Write(" with PID: ");
			Console.ForegroundColor = ConsoleColor.Green;
			Console.WriteLine(processes[^1].Id);
			Console.ResetColor();

			IntPtr allocatedMem = WinAPI.VirtualAllocEx(processes[^1].Handle, IntPtr.Zero, (uint)((Encoding.Unicode.GetBytes(dllPath).Length + 1) * (Marshal.SizeOf(typeof(char)) * 2)), WinAPI.AllocationType.MEM_RESERVE | WinAPI.AllocationType.MEM_COMMIT, WinAPI.MemoryProtection.PAGE_READWRITE);
			if (allocatedMem == IntPtr.Zero)
			{
				Console.ForegroundColor = ConsoleColor.DarkRed;
				Console.Write("Can't allocate memory in ");
				Console.ForegroundColor = ConsoleColor.Red;
				Console.Write(processName);
				Console.ForegroundColor = ConsoleColor.DarkRed;
				Console.WriteLine(" to write");
				Console.ResetColor();
				Console.WriteLine("Catched error code: " + Marshal.GetLastWin32Error());
				return 1;
			}
            if (!WinAPI.WriteProcessMemory(processes[^1].Handle, allocatedMem, Encoding.Unicode.GetBytes(dllPath), (uint)((Encoding.Unicode.GetBytes(dllPath).Length + 1) * (Marshal.SizeOf(typeof(char)) * 2)), out _))
            {
                Console.ForegroundColor = ConsoleColor.DarkRed;
                Console.Write("Can't write dll path to ");
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine(processName);
                Console.ResetColor();
                Console.WriteLine("Catched error code: " + Marshal.GetLastWin32Error());
                return 1;
            }
			IntPtr kernel32 = WinAPI.GetModuleHandleW("kernel32.dll");
			if (kernel32 == IntPtr.Zero)
			{
				Console.ForegroundColor = ConsoleColor.DarkRed;
				Console.Write("Can't get kernel32.dll handle");
				Console.ResetColor();
				Console.WriteLine("Catched error code: " + Marshal.GetLastWin32Error());
				return 1;
			}
			IntPtr loadLibraryAddr = WinAPI.GetProcAddress(kernel32, "LoadLibraryW");
			if (loadLibraryAddr == IntPtr.Zero)
			{
				Console.ForegroundColor = ConsoleColor.DarkRed;
				Console.Write("Can't get LoadLibraryW address from kernel32.dll");
				Console.ResetColor();
				Console.WriteLine("Catched error code: " + Marshal.GetLastWin32Error());
				return 1;
			}
			IntPtr thread = WinAPI.CreateRemoteThread(processes[^1].Handle, IntPtr.Zero, 0, loadLibraryAddr, allocatedMem, 0, out _);
            if (thread == IntPtr.Zero)
			{
				Console.ForegroundColor = ConsoleColor.DarkRed;
				Console.Write("Can't create remote thread with LoadLibrary module in ");
				Console.ForegroundColor = ConsoleColor.Red;
				Console.WriteLine(processName);
				Console.ResetColor();
				Console.WriteLine("Catched error code: " + Marshal.GetLastWin32Error());
				return 1;
			}

			Console.ForegroundColor = ConsoleColor.DarkGreen;
			Console.Write("Successfully injected ");
			Console.ForegroundColor = ConsoleColor.Cyan;
			Console.Write(dllname);
			Console.ForegroundColor = ConsoleColor.DarkYellow;
			Console.Write(" into ");
			Console.ForegroundColor = ConsoleColor.Red;
			Console.WriteLine(processName);
			Console.ResetColor();

			Console.ForegroundColor = ConsoleColor.White;
			Console.WriteLine("You have 5 seconds to read this information, GOODBYE");
			Console.ResetColor();

			Thread.Sleep(5000);

			return 0;
		}
	}
}
