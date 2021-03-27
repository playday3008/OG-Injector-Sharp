//#define OSIRIS
//#define GOESP
//#define BETA

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net.Http;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;

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

    class Artifacts
    {
        [JsonPropertyName("id")]
        public int ID { get; set; }
        [JsonPropertyName("node_id")]
        public string NodeIDBase64 { get; set; }
        [JsonPropertyName("name")]
        public string Name { get; set; }
        [JsonPropertyName("size_in_bytes")]
        public int SizeInBytes { get; set; }
        [JsonPropertyName("url")]
        public Uri Url { get; set; }
        [JsonPropertyName("archive_download_url")]
        public Uri ArchiveUrl { get; set; }
        [JsonPropertyName("expired")]
        public bool Experied { get; set; }
        [JsonPropertyName("created_at")]
        public DateTime CreatedAt { get; set; }
        [JsonPropertyName("updated_at")]
        public DateTime UpdatedAt { get; set; }
        [JsonPropertyName("expires_at")]
        public DateTime ExperiesAt { get; set; }
    }

    class Actions
    {
        [JsonPropertyName("total_count")]
        public int Count { get; set; }
        [JsonPropertyName("artifacts")]
        public Artifacts[] Artifacts { get; set; }
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
                    Color.DarkRed(); Console.WriteLine("Can't write original NtOpenFile bytes to ");
                    Color.Red(); Console.WriteLine(processName);
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

        private static void Exception(Exception e)
        {
            Color.DarkRed();    Console.WriteLine("Whoopsy I catch the fucking exception:");
            Color.Red();        Console.WriteLine("Message: " + e.Message);
            Console.ResetColor();
            if (e.HelpLink != null)
                Console.WriteLine("Help link: " + e.HelpLink);
        }

        private static bool FileIsLocked(string fileName)
        {
            try
            {
                using FileStream fileStream = File.Open(fileName, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
                if (fileStream != null)
                    fileStream.Close();
                return false;
            }
            catch (IOException)
            {
                return true;
            }
        }

        private static readonly HttpClient httpClient = new();

        private static async Task<bool> GetDllIfOutdated(string outputDll)
        {
            string githubApiString = "https://api.github.com/repos/playday3008/";
            string latestFileName = null;
            try
            {
                latestFileName = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData) + @"\.OG-Injector-";
            }
            catch (Exception e)
            {
                Exception(e);
                return false;
            }

        #if OSIRIS || GOESP
            if (outputDll.Contains("Osiris"))
            {
                githubApiString += "Osiris";
                latestFileName += "Osiris";
            }
            else if (outputDll.Contains("GOESP"))
            {
                githubApiString += "GOESP";
                latestFileName += "GOESP";
            }
        #endif

            githubApiString += "/actions/artifacts";

            httpClient.DefaultRequestHeaders.Authorization = new("token", "6ab7fad6f911037ce34796c383a33bedc09cae3b"); // GitHub personal access token with "public_repo" premission
            httpClient.DefaultRequestHeaders.Accept.ParseAdd("application/vnd.github.v3+json");
            httpClient.DefaultRequestHeaders.UserAgent.ParseAdd("OG-Injector-Sharp");
            HttpResponseMessage response;
            try
            {
                response = await httpClient.GetAsync(githubApiString);
            }
            catch (Exception e)
            {
                Exception(e);
                return false;
            }
            if (!response.IsSuccessStatusCode)
            {
                Color.DarkRed();    Console.Write("Can't connect to GitHub API. Returned code: ");
                Color.Red();        Console.WriteLine(response.StatusCode);
                Console.ResetColor();
                if (File.Exists(outputDll))
                {
                    if (File.Exists(latestFileName))
                    {
                        IEnumerable<string> readed = await Task.Run(() => File.ReadLines(latestFileName, Encoding.Unicode));
                        List<string> readedAsList = readed.ToList();

                        using SHA512CryptoServiceProvider cryptoProvider = new();
                        string hash = BitConverter.ToString(cryptoProvider.ComputeHash(File.OpenRead(outputDll)));

                        if (hash == readedAsList[1])
                        {
                            Color.DarkYellow(); Console.Write("Skipping checking for updates, because there is no connection to GitHub, but \"");
                            Color.Yellow();     Console.Write(outputDll);
                            Color.DarkYellow(); Console.WriteLine("\" was found and SHA512 checksum matched");
                            Console.ResetColor();
                            return true;
                        }
                        else
                        {
                            Color.DarkYellow(); Console.Write("Skipping checking for updates, because there is no connection to GitHub, but \"");
                            Color.Yellow();     Console.Write(outputDll);
                            Color.DarkYellow(); Console.Write("\" was found but SHA512 checksum");
                            Color.Red();        Console.Write(" NOT ");
                            Color.DarkYellow(); Console.WriteLine("matched");
                            Console.ResetColor();
                            return true;
                        }
                    }
                    else
                    {
                        Color.DarkYellow(); Console.Write("Skipping checking for updates, because there is no connection to GitHub, but \"");
                        Color.Yellow();     Console.Write(outputDll);
                        Color.DarkYellow(); Console.WriteLine("\" was found");
                        Console.ResetColor();
                        return true;
                    }
                }
                return false;
            }

            JsonDocument jsonParsed;
            Actions actions;
            try
            {
                jsonParsed = await JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync());
                actions = await Task.Run(() => JsonSerializer.Deserialize<Actions>(jsonParsed.RootElement.GetRawText()));
            }
            catch (Exception e)
            {
                Exception(e);
                return false;
            }

            if (File.Exists(latestFileName))
            {
                IEnumerable<string> readed = await Task.Run(() => File.ReadLines(latestFileName, Encoding.Unicode));
                List<string> readedAsList = readed.ToList();
                if (actions.Count == Convert.ToInt32(readedAsList[0]))
                {
                    if (File.Exists(outputDll))
                    {
                        using SHA512CryptoServiceProvider cryptoProvider = new();
                        string hash = BitConverter.ToString(cryptoProvider.ComputeHash(File.OpenRead(outputDll)));

                        if (hash == readedAsList[1])
                        {
                            Color.DarkGreen();  Console.Write("No updates for: ");
                            Color.Green();      Console.WriteLine(outputDll);
                            Color.DarkGreen();  Console.Write("SHA512 checksum matched: ");
                            Color.Green();      Console.WriteLine(hash.Replace("-", string.Empty));
                            Console.ResetColor();
                            return true;
                        }
                        else
                        {
                            Color.DarkGreen();  Console.Write("No updates for: ");
                            Color.Green();      Console.WriteLine(outputDll);
                            Color.DarkYellow(); Console.WriteLine("But SHA512 checksum NOT matched, redownloading");
                            Console.ResetColor();
                        }
                    }
                }
                if ((File.GetAttributes(latestFileName) & FileAttributes.ReadOnly) == FileAttributes.ReadOnly)
                    File.SetAttributes(latestFileName, FileAttributes.Hidden | FileAttributes.NotContentIndexed);
                await File.WriteAllTextAsync(latestFileName, actions.Count.ToString(), Encoding.Unicode);
                File.SetAttributes(latestFileName, FileAttributes.Hidden | FileAttributes.NotContentIndexed | FileAttributes.ReadOnly);
            }
            else
            {
                await File.WriteAllTextAsync(latestFileName, actions.Count.ToString(), Encoding.Unicode);
                File.SetAttributes(latestFileName, FileAttributes.Hidden | FileAttributes.NotContentIndexed | FileAttributes.ReadOnly);
            }

            Uri zipUrl = null;
            foreach (Artifacts i in actions.Artifacts)
            {
                if (i.Name.Contains("Windows"))
            #if OSIRIS || GOESP
                    if (i.Name.Contains("BETA") == outputDll.Contains("BETA"))
                    if ((outputDll.Contains("SSE2") && i.Name.Contains("SSE2")) || (outputDll.Contains("AVX.") && i.Name.Contains("AVX") && !i.Name.EndsWith('2')) || (outputDll.Contains("AVX2") && i.Name.Contains("AVX2")))
            #endif
                        {
                            if (i.Experied)
                            {
                                Color.DarkYellow(); Console.Write("There is no downloadable \"");
                                Color.Yellow();     Console.Write(outputDll);
                                Color.DarkYellow(); Console.WriteLine("\" at the moment");
                                Console.ResetColor();
                                return false;
                            }
                            Color.DarkGreen();  Console.Write("Update available for: ");
                            Color.Green();      Console.WriteLine(outputDll);
                            Color.DarkGreen();  Console.Write("Created at: ");
                            Color.Green();      Console.WriteLine(i.CreatedAt.ToLongTimeString());
                            Console.ResetColor();
                            zipUrl = i.ArchiveUrl;
                            break;
                        }
            }

            HttpResponseMessage downloadResponse = await httpClient.GetAsync(zipUrl);
            if (downloadResponse.IsSuccessStatusCode)
            {
                Color.DarkGreen();  Console.Write("Downloading latest: ");
                Color.Green();      Console.WriteLine(outputDll);
                Console.ResetColor();
            }
            else
            {
                Color.DarkRed();    Console.Write("Cant download latest ");
                Color.Red();        Console.WriteLine(outputDll);
                Console.ResetColor();
                if (File.Exists(outputDll))
                {
                    Color.DarkYellow();
                    Console.WriteLine("Use available dll instead");
                    Console.ResetColor();
                    return true;
                }
                return false;
            }

            string tempFile = Path.GetTempFileName();

            try
            {
                using FileStream zipStream = new(tempFile, FileMode.Truncate);
                await zipStream.WriteAsync(await httpClient.GetByteArrayAsync(downloadResponse.RequestMessage.RequestUri));
                zipStream.Close();
                if (File.Exists(outputDll))
                    File.Delete(outputDll);
                ZipFile.ExtractToDirectory(tempFile, Directory.GetCurrentDirectory(), true);
            }
            catch (Exception e)
            {
                Exception(e);
                return false;
            }

            {
                using SHA512CryptoServiceProvider cryptoProvider = new();
                string hash = BitConverter.ToString(cryptoProvider.ComputeHash(File.OpenRead(outputDll)));

                if ((File.GetAttributes(latestFileName) & FileAttributes.ReadOnly) == FileAttributes.ReadOnly)
                    File.SetAttributes(latestFileName, FileAttributes.Hidden | FileAttributes.NotContentIndexed);
                await File.AppendAllTextAsync(latestFileName, "\n" + hash, Encoding.Unicode);
                File.SetAttributes(latestFileName, FileAttributes.Hidden | FileAttributes.NotContentIndexed | FileAttributes.ReadOnly);
            }

            return true;
        }

        static async Task<int> Main(string[] args)
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
            Console.WriteLine();
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
            if (System.Runtime.Intrinsics.X86.Avx2.IsSupported)
                dllname += "_AVX2.dll";
            else if (System.Runtime.Intrinsics.X86.Avx.IsSupported)
                dllname += "_AVX.dll";
            else if (System.Runtime.Intrinsics.X86.Sse2.IsSupported)
                dllname += "_SSE2.dll";
            else
            {
                Color.DarkRed(); Console.WriteLine("Unsupported CPU intrinsics!");
                Color.White();   Console.WriteLine("Press any key to continue...");
                Console.ResetColor();
                Console.ReadKey();
                return 1;
            }
        #endif

            if (File.Exists(dllname) && FileIsLocked(dllname))
            {
                Color.DarkYellow();
                Console.WriteLine("Skipping update check, because \"" + dllname + "\" file is locked");
                Console.ResetColor();
            }
            else
            {
                Color.DarkYellow();
                Console.WriteLine("Checking for " + dllname + " updates");
                Console.ResetColor();
                if (!await GetDllIfOutdated(dllname))
                {
                    Color.White();
                    Console.WriteLine("Press any key to continue...");
                    Console.ResetColor();
                    Console.ReadKey();
                    return 1;
                }
            }

            if (File.Exists(dllname))
            {
                Color.DarkGreen();  Console.Write("DLL: ");
                Color.Green();      Console.Write(dllname);
                Color.DarkGreen();  Console.WriteLine(" found");
                Console.ResetColor();
            }
            else
            {
                Color.DarkRed();    Console.Write("Can't find: ");
                Color.Red();        Console.WriteLine(dllname);
                Color.White();      Console.WriteLine("Press any key to continue...");
                Console.ResetColor();
                Console.ReadKey();
                return 1;
            }

            string processName = "csgo.exe";

            Color.DarkYellow(); Console.Write("Finding ");
            Color.Red();        Console.Write(processName);
            Color.DarkYellow(); Console.WriteLine(" process");
            Console.ResetColor();

            Process[] processes = Process.GetProcessesByName(Path.GetFileNameWithoutExtension(processName));

            if (processes.Length == 0)
            {
                Color.DarkRed();    Console.Write("Can't find: ");
                Color.Red();        Console.WriteLine(processName);
                Color.White();      Console.WriteLine("Press any key to continue...");
                Console.ResetColor();
                Console.ReadKey();
                return 1;
            }
            else if (processes.Length > 1)
            {
                Color.DarkGreen();  Console.Write("Process: ");
                Color.Green();      Console.Write(processName);
                Color.DarkGreen();  Console.Write(" found with PID's:");
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
                Color.DarkYellow(); Console.Write("Use the latest started process available in the list above: ");
                Color.Yellow();     Console.WriteLine(processes[^1].Id);
                Console.ResetColor();
            }
            else
            {
                Color.DarkGreen();  Console.Write("Process: ");
                Color.Green();      Console.Write(processName);
                Color.DarkGreen();  Console.Write(" found with PID: ");
                Color.Green();      Console.WriteLine(processes[^1].Id);
                Console.ResetColor();
            }

            if (!Bypass(processes[^1], processName))
                return 1;

            string dllPath = Path.GetFullPath(dllname);

            Color.DarkYellow(); Console.Write("Injecting ");
            Color.Yellow();     Console.Write(dllname);
            Color.DarkYellow(); Console.Write(" into ");
            Color.Green();      Console.Write(processName);
            Color.DarkYellow(); Console.Write(" with PID: ");
            Color.Green();      Console.WriteLine(processes[^1].Id);
            Console.ResetColor();

            IntPtr allocatedMem = WinAPI.VirtualAllocEx(processes[^1].Handle, IntPtr.Zero, (uint)Encoding.Unicode.GetBytes(dllPath).Length + 1, WinAPI.AllocationType.MEM_RESERVE | WinAPI.AllocationType.MEM_COMMIT, WinAPI.MemoryProtection.PAGE_READWRITE);
            if (allocatedMem == IntPtr.Zero)
            {
                Color.DarkRed();    Console.Write("Can't allocate memory in ");
                Color.Red();        Console.Write(processName);
                Color.DarkRed();    Console.WriteLine(" to write");
                Console.ResetColor();
                Console.WriteLine("Catched error code: " + Marshal.GetLastWin32Error());
                Color.White();      Console.WriteLine("Press any key to continue...");
                Console.ResetColor();
                Console.ReadKey();
                return 1;
            }
            if (!WinAPI.WriteProcessMemory(processes[^1].Handle, allocatedMem, Encoding.Unicode.GetBytes(dllPath), (uint)(uint)Encoding.Unicode.GetBytes(dllPath).Length + 1, out _))
            {
                Color.DarkRed();    Console.Write("Can't write dll path to ");
                Color.Red();        Console.WriteLine(processName);
                Console.ResetColor();
                Console.WriteLine("Catched error code: " + Marshal.GetLastWin32Error());
                Color.White();      Console.WriteLine("Press any key to continue...");
                Console.ResetColor();
                Console.ReadKey();
                return 1;
            }
            IntPtr kernel32 = WinAPI.GetModuleHandleW("kernel32.dll");
            if (kernel32 == IntPtr.Zero)
            {
                Color.DarkRed();    Console.Write("Can't get kernel32.dll handle");
                Console.ResetColor();
                Console.WriteLine("Catched error code: " + Marshal.GetLastWin32Error());
                Color.White();      Console.WriteLine("Press any key to continue...");
                Console.ResetColor();
                Console.ReadKey();
                return 1;
            }
            IntPtr loadLibraryAddr = WinAPI.GetProcAddress(kernel32, "LoadLibraryW");
            if (loadLibraryAddr == IntPtr.Zero)
            {
                Color.DarkRed();    Console.Write("Can't get LoadLibraryW address from kernel32.dll");
                Console.ResetColor();
                Console.WriteLine("Catched error code: " + Marshal.GetLastWin32Error());
                Color.White();      Console.WriteLine("Press any key to continue...");
                Console.ResetColor();
                Console.ReadKey();
                return 1;
            }
            IntPtr thread = WinAPI.CreateRemoteThread(processes[^1].Handle, IntPtr.Zero, 0, loadLibraryAddr, allocatedMem, 0, out _);
            if (thread == IntPtr.Zero)
            {
                Color.DarkRed();    Console.Write("Can't create remote thread with LoadLibrary module in ");
                Color.Red();        Console.WriteLine(processName);
                Console.ResetColor();
                Console.WriteLine("Catched error code: " + Marshal.GetLastWin32Error());
                Color.White();      Console.WriteLine("Press any key to continue...");
                Console.ResetColor();
                Console.ReadKey();
                return 1;
            }

            Color.DarkGreen();  Console.Write("Successfully injected ");
            Color.Cyan();       Console.Write(dllname);
            Color.DarkYellow(); Console.Write(" into ");
            Color.Red();        Console.WriteLine(processName);
            Console.ResetColor();

            Color.White(); Console.WriteLine("You have 5 seconds to read this information, GOODBYE");
            Console.ResetColor();

            Thread.Sleep(5000);

            return 0;
        }
    }
}
