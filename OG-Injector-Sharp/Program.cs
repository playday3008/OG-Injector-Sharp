using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

namespace OGInjector
{
    class Color
    {
        public static void Black()
        {
            Console.ForegroundColor = ConsoleColor.Black;
        }
        public static void DarkBlue()
        {
            Console.ForegroundColor = ConsoleColor.DarkBlue;
        }
        public static void DarkGreen()
        {
            Console.ForegroundColor = ConsoleColor.DarkGreen;
        }
        public static void DarkCyan()
        {
            Console.ForegroundColor = ConsoleColor.DarkCyan;
        }
        public static void DarkRed()
        {
            Console.ForegroundColor = ConsoleColor.DarkRed;
        }
        public static void DarkMagenta()
        {
            Console.ForegroundColor = ConsoleColor.DarkMagenta;
        }
        public static void DarkYellow()
        {
            Console.ForegroundColor = ConsoleColor.DarkYellow;
        }
        public static void Gray()
        {
            Console.ForegroundColor = ConsoleColor.Gray;
        }
        public static void DarkGray()
        {
            Console.ForegroundColor = ConsoleColor.DarkGray;
        }
        public static void Blue()
        {
            Console.ForegroundColor = ConsoleColor.Blue;
        }
        public static void Green()
        {
            Console.ForegroundColor = ConsoleColor.Green;
        }
        public static void Cyan()
        {
            Console.ForegroundColor = ConsoleColor.Cyan;
        }
        public static void Red()
        {
            Console.ForegroundColor = ConsoleColor.Red;
        }
        public static void Magenta()
        {
            Console.ForegroundColor = ConsoleColor.Magenta;
        }
        public static void Yellow()
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
        }
        public static void White()
        {
            Console.ForegroundColor = ConsoleColor.White;
        }
    }

    class Program
    {
        private static bool Bypass(Process process, string processName)
        {
            IntPtr ntdll = WinAPI.LoadLibraryW("ntdll");
            if (ntdll == IntPtr.Zero)
            {
                Color.DarkRed(); Console.WriteLine("Can't load ntdll.dll module");
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
                    Color.DarkRed();    Console.Write("Can't write original NtOpenFile bytes to ");
                    Color.Red();        Console.WriteLine(processName);
                    Console.ResetColor();
                    Console.WriteLine("Catched error code: " + Marshal.GetLastWin32Error());
                    return false;
                }
                return true;
            }
            else
            {
                Color.DarkRed(); Console.WriteLine("Can't find NtOpenFile into ntdll.dll");
                Console.ResetColor();
                Console.WriteLine("Catched error code: " + Marshal.GetLastWin32Error());
                return false;
            }
        }

        static int Main(string[] args)
        {
            Console.OutputEncoding = Encoding.Unicode;
            Console.Title = "OG Injector by PlayDay";
            Color.Red();     Console.WriteLine(@"   ____  ______   ____        _           __            "); Thread.Sleep(50);
            Color.Green();   Console.WriteLine(@"  / __ \/ ____/  /  _/___    (_)__  _____/ /_____  _____"); Thread.Sleep(50);
            Color.Yellow();  Console.WriteLine(@" / / / / / __    / // __ \  / / _ \/ ___/ __/ __ \/ ___/"); Thread.Sleep(50);
            Color.Blue();    Console.WriteLine(@"/ /_/ / /_/ /  _/ // / / / / /  __/ /__/ /_/ /_/ / /    "); Thread.Sleep(50);
            Color.Magenta(); Console.WriteLine(@"\____/\____/  /___/_/ /_/_/ /\___/\___/\__/\____/_/     "); Thread.Sleep(50);
            Color.Cyan();    Console.WriteLine(@"    ____  __           /___/                   __ __    "); Thread.Sleep(50);
            Color.Red();     Console.WriteLine(@"   / __ \/ /___ ___  __/ __ \____ ___  __   __/ // /_   "); Thread.Sleep(50);
            Color.Green();   Console.WriteLine(@"  / /_/ / / __ `/ / / / / / / __ `/ / / /  /_  _  __/   "); Thread.Sleep(50);
            Color.Yellow();  Console.WriteLine(@" / ____/ / /_/ / /_/ / /_/ / /_/ / /_/ /  /_  _  __/    "); Thread.Sleep(50);
            Color.Blue();    Console.WriteLine(@"/_/   /_/\__,_/\__, /_____/\__,_/\__, /    /_//_/       "); Thread.Sleep(50);
            Color.Magenta(); Console.WriteLine(@"              /____/            /____/                  "); Thread.Sleep(50);
            Console.WriteLine("");
            Console.ResetColor();

        #if OSIRIS
            string libraryName = "Osiris";
        #elif GOESP
            string libraryName = "GOESP";
        #else
            string libraryName = "library.dll";
        #endif

        #if (OSIRIS || GOESP) && BETA
            libraryName += "_BETA";
        #endif

        #if OSIRIS || GOESP
            if (System.Runtime.Intrinsics.X86.Avx2.IsSupported)
                libraryName += "_AVX2.dll";
            else if (System.Runtime.Intrinsics.X86.Avx.IsSupported)
                libraryName += "_AVX.dll";
            else if (System.Runtime.Intrinsics.X86.Sse2.IsSupported)
                libraryName += "_SSE2.dll";
            else
            {
                Color.DarkRed(); Console.WriteLine("Unsupported CPU intrinsics!");
                Color.White();   Console.WriteLine("Press any key to continue...");
                Console.ResetColor();
                Console.ReadKey();
                return 1;
            }
        #endif

            if (File.Exists(libraryName))
            {
                Color.DarkGreen();   Console.Write("Library: ");
                Color.Green();       Console.Write(libraryName);
                Color.DarkGreen();   Console.WriteLine(" found");
                Console.ResetColor();
            }
            else
            {
                Color.DarkRed(); Console.Write("Can't find: ");
                Color.Red();     Console.WriteLine(libraryName);
                Color.White();   Console.WriteLine("Press any key to continue...");
                Console.ResetColor();
                Console.ReadKey();
                return 1;
            }

            string processName = "csgo.exe";

            Color.DarkYellow();  Console.Write("Finding ");
            Color.Red();         Console.Write(processName);
            Color.DarkYellow();  Console.WriteLine(" process");
            Console.ResetColor();

            Process[] processes = Process.GetProcessesByName(Path.GetFileNameWithoutExtension(processName));

            if (processes.Length == 0)
            {
                Color.DarkRed(); Console.Write("Can't find: ");
                Color.Red();     Console.WriteLine(processName);
                Color.White();   Console.WriteLine("Press any key to continue...");
                Console.ResetColor();
                Console.ReadKey();
                return 1;
            }
            else if (processes.Length > 1)
            {
                Color.DarkGreen();   Console.Write("Process: ");
                Color.Green();       Console.Write(processName);
                Color.DarkGreen();   Console.Write(" found with PID's:");
                int pcounter = 0;
                processes = processes.OrderBy(f => f.StartTime).ToArray();
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
                Color.DarkYellow();  Console.Write("Use the latest started process available in the list above: ");
                Color.Yellow();      Console.WriteLine(processes[^1].Id);
                Console.ResetColor();
            }
            else
            {
                Color.DarkGreen();   Console.Write("Process: ");
                Color.Green();       Console.Write(processName);
                Color.DarkGreen();   Console.Write(" found with PID: ");
                Color.Green();       Console.WriteLine(processes[^1].Id);
                Console.ResetColor();
            }

            if (!Bypass(processes[^1], processName))
            {
                Color.White(); Console.WriteLine("Press any key to continue...");
                Console.ResetColor();
                Console.ReadKey();
                return 1;
            }

            string libraryPath = Path.GetFullPath(libraryName);

            Color.DarkYellow();  Console.Write("Injecting ");
            Color.Yellow();      Console.Write(libraryName);
            Color.DarkYellow();  Console.Write(" into ");
            Color.Green();       Console.Write(processName);
            Color.DarkYellow();  Console.Write(" with PID: ");
            Color.Green();       Console.WriteLine(processes[^1].Id);
            Console.ResetColor();

            if (!WinInject.Inject(processes[^1], processName, libraryPath))
            {
                Color.White(); Console.WriteLine("Press any key to continue...");
                Console.ResetColor();
                Console.ReadKey();
                return 1;
            }

            Color.DarkGreen();  Console.Write("Successfully injected ");
            Color.Cyan();       Console.Write(libraryName);
            Color.DarkYellow(); Console.Write(" into ");
            Color.Red();        Console.WriteLine(processName);
            Console.ResetColor();

            Color.White();      Console.WriteLine("You have 5 seconds to read this information, GOODBYE");
            Console.ResetColor();

            Thread.Sleep(5000);

            return 0;
        }
    }
}
