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
        public string NodeID { get; set; }
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

        private static async Task<bool> GetLibraryIfOutdated(string outputLibrary)
        {
            try
            {
                string githubApiString = "https://api.github.com/repos/playday3008/";
                string latestFileName = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData) + @"\.OG-Injector-";

            #if OSIRIS || GOESP
                if (outputLibrary.Contains("Osiris"))
                {
                    githubApiString += "Osiris";
                    latestFileName += "Osiris";
                }
                else if (outputLibrary.Contains("GOESP"))
                {
                    githubApiString += "GOESP";
                    latestFileName += "GOESP";
                }
            #endif

                githubApiString += "/actions/artifacts";

                httpClient.DefaultRequestHeaders.Authorization = new("token", "6ab7fad6f911037ce34796c383a33bedc09cae3b"); // GitHub personal access token with "public_repo" premission
                httpClient.DefaultRequestHeaders.Accept.ParseAdd("application/vnd.github.v3+json");
                httpClient.DefaultRequestHeaders.UserAgent.ParseAdd("OG-Injector-Sharp");
                HttpResponseMessage response = null;
                response = await httpClient.GetAsync(githubApiString);
                if (!response.IsSuccessStatusCode)
                {
                    Color.DarkRed();    Console.Write("Can't connect to GitHub API. Returned code: ");
                    Color.Red();        Console.WriteLine(response.StatusCode);
                    Console.ResetColor();
                    if (File.Exists(outputLibrary))
                    {
                        if (File.Exists(latestFileName))
                        {
                            IEnumerable<string> readed = await Task.Run(() => File.ReadLines(latestFileName, Encoding.Unicode));
                            List<string> readedAsList = readed.ToList();

                            if (readedAsList.Count > 1)
                            {
                                using SHA512CryptoServiceProvider cryptoProvider = new();
                                string hash = BitConverter.ToString(cryptoProvider.ComputeHash(File.OpenRead(outputLibrary)));

                                Color.DarkYellow(); Console.Write("Skipping checking for updates, because there is no connection to GitHub, but \"");
                                Color.Yellow();     Console.Write(outputLibrary);

                                if (hash == readedAsList[1])
                                {
                                    Color.DarkYellow(); Console.WriteLine("\" was found and SHA512 checksum matched");
                                    Console.ResetColor();
                                    return true;
                                }
                            }
                            Color.DarkYellow(); Console.Write("\" was found but SHA512 checksum");
                            Color.Red();        Console.Write(" NOT ");
                            Color.DarkYellow(); Console.WriteLine("matched");
                            Console.ResetColor();
                            return true;
                        }
                        else
                        {
                            Color.DarkYellow(); Console.Write("Skipping checking for updates, because there is no connection to GitHub, but \"");
                            Color.Yellow();     Console.Write(outputLibrary);
                            Color.DarkYellow(); Console.WriteLine("\" was found");
                            Console.ResetColor();
                            return true;
                        }
                    }
                    else
                    {
                        Color.DarkYellow(); Console.Write("Skipping checking for updates, because there is no connection to GitHub, and \"");
                        Color.Yellow();     Console.Write(outputLibrary);
                        Color.DarkYellow(); Console.WriteLine("\" is missing so, exiting");
                        Console.ResetColor();
                        return false;
                    }
                }
                else
                {
                    Color.DarkGreen(); Console.Write("Connected to GitHub API. Returned code: ");
                    Console.WriteLine(response.StatusCode);
                    Console.ResetColor();
                }

                JsonDocument jsonParsed = await JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync());
                Actions actions = await Task.Run(() => JsonSerializer.Deserialize<Actions>(jsonParsed.RootElement.GetRawText()));

                if (File.Exists(latestFileName))
                {
                    IEnumerable<string> readed = await Task.Run(() => File.ReadLines(latestFileName, Encoding.Unicode));
                    List<string> readedAsList = readed.ToList();
                    if (actions.Count == Convert.ToInt32(readedAsList[0]))
                    {
                        if (File.Exists(outputLibrary))
                        {
                            if (readedAsList.Count > 1)
                            {
                                using SHA512CryptoServiceProvider cryptoProvider = new();
                                string hash = BitConverter.ToString(cryptoProvider.ComputeHash(File.OpenRead(outputLibrary)));

                                if (hash == readedAsList[1])
                                {
                                    Color.DarkGreen();  Console.Write("No updates for: ");
                                    Color.Green();      Console.WriteLine(outputLibrary);
                                    Color.DarkGreen();  Console.Write("SHA512 checksum matched: ");
                                    Color.Green();      Console.WriteLine(hash.Replace("-", string.Empty));
                                    Console.ResetColor();
                                    return true;
                                }
                            }
                            Color.DarkGreen();  Console.Write("No updates for: ");
                            Color.Green();      Console.WriteLine(outputLibrary);
                            Color.DarkYellow(); Console.WriteLine("But SHA512 checksum NOT matched, redownloading");
                            Console.ResetColor();
                        }
                    }
                    File.SetAttributes(latestFileName, FileAttributes.Normal);
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
                        if (i.Name.Contains("BETA") == outputLibrary.Contains("BETA"))
                            if ((outputLibrary.Contains("SSE2") && i.Name.Contains("SSE2")) || (outputLibrary.Contains("AVX.") && i.Name.Contains("AVX") && !i.Name.EndsWith('2')) || (outputLibrary.Contains("AVX2") && i.Name.Contains("AVX2")))
                #endif
                            {
                                if (i.Experied)
                                {
                                    Color.DarkYellow(); Console.Write("There is no downloadable \"");
                                    Color.Yellow();     Console.Write(outputLibrary);
                                    Color.DarkYellow(); Console.WriteLine("\" at the moment");
                                    Console.ResetColor();
                                    return false;
                                }
                                Color.DarkGreen();  Console.Write("Update available for: ");
                                Color.Green();      Console.WriteLine(outputLibrary);
                                Color.DarkGreen();  Console.Write("Created at: ");
                                Color.Green();      Console.WriteLine(i.CreatedAt.ToLocalTime());
                                Console.ResetColor();
                                zipUrl = i.ArchiveUrl;
                                break;
                            }
                }

                HttpResponseMessage downloadResponse = await httpClient.GetAsync(zipUrl);
                if (downloadResponse.IsSuccessStatusCode)
                {
                    Color.DarkGreen();  Console.Write("Downloading latest: ");
                    Color.Green();      Console.WriteLine(outputLibrary);
                    Console.ResetColor();
                }
                else
                {
                    Color.DarkRed();    Console.Write("Cant download latest ");
                    Color.Red();        Console.WriteLine(outputLibrary);
                    Console.ResetColor();
                    if (File.Exists(outputLibrary))
                    {
                        Color.DarkYellow();
                        Console.WriteLine("Use available library instead");
                        Console.ResetColor();
                        return true;
                    }
                    return false;
                }

                string tempFile = Path.GetTempFileName();

                using FileStream zipStream = new(tempFile, FileMode.Truncate);
                await zipStream.WriteAsync(await httpClient.GetByteArrayAsync(downloadResponse.RequestMessage.RequestUri));
                zipStream.Close();

                File.SetAttributes(outputLibrary, FileAttributes.Normal);
                ZipFile.ExtractToDirectory(tempFile, Directory.GetCurrentDirectory(), true);

                {
                    using SHA512CryptoServiceProvider cryptoProvider = new();
                    string hash = BitConverter.ToString(cryptoProvider.ComputeHash(File.OpenRead(outputLibrary)));

                    File.SetAttributes(latestFileName, FileAttributes.Normal);
                    await File.AppendAllTextAsync(latestFileName, "\n" + hash, Encoding.Unicode);
                    File.SetAttributes(latestFileName, FileAttributes.Hidden | FileAttributes.NotContentIndexed | FileAttributes.ReadOnly);
                }
            }
            catch (Exception e)
            {
                Exception(e);
                return false;
            }

            return true;
        }

        static async Task<int> Main(string[] args)
        {
            Console.OutputEncoding = Encoding.Unicode;
            Console.Title = "OG Injector by PlayDay";
            Color.Red();        Console.WriteLine(@"   ____  ______   ____        _           __            "); Thread.Sleep(50);
            Color.Green();      Console.WriteLine(@"  / __ \/ ____/  /  _/___    (_)__  _____/ /_____  _____"); Thread.Sleep(50);
            Color.Yellow();     Console.WriteLine(@" / / / / / __    / // __ \  / / _ \/ ___/ __/ __ \/ ___/"); Thread.Sleep(50);
            Color.Blue();       Console.WriteLine(@"/ /_/ / /_/ /  _/ // / / / / /  __/ /__/ /_/ /_/ / /    "); Thread.Sleep(50);
            Color.Magenta();    Console.WriteLine(@"\____/\____/  /___/_/ /_/_/ /\___/\___/\__/\____/_/     "); Thread.Sleep(50);
            Color.Cyan();       Console.WriteLine(@"    ____  __           /___/                   __ __    "); Thread.Sleep(50);
            Color.Red();        Console.WriteLine(@"   / __ \/ /___ ___  __/ __ \____ ___  __   __/ // /_   "); Thread.Sleep(50);
            Color.Green();      Console.WriteLine(@"  / /_/ / / __ `/ / / / / / / __ `/ / / /  /_  _  __/   "); Thread.Sleep(50);
            Color.Yellow();     Console.WriteLine(@" / ____/ / /_/ / /_/ / /_/ / /_/ / /_/ /  /_  _  __/    "); Thread.Sleep(50);
            Color.Blue();       Console.WriteLine(@"/_/   /_/\__,_/\__, /_____/\__,_/\__, /    /_//_/       "); Thread.Sleep(50);
            Color.Magenta();    Console.WriteLine(@"              /____/            /____/                  "); Thread.Sleep(50);
            Console.WriteLine();
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
                Color.DarkRed();    Console.WriteLine("Unsupported CPU intrinsics!");
                Color.White();      Console.WriteLine("Press any key to continue...");
                Console.ResetColor();
                Console.ReadKey();
                return 1;
            }
        #endif

            if (File.Exists(libraryName) && FileIsLocked(libraryName))
            {
                Color.DarkYellow();
                Console.WriteLine("Skipping update check, because \"" + libraryName + "\" file is locked");
                Console.ResetColor();
            }
            else
            {
                Color.DarkYellow();
                Console.WriteLine("Checking for " + libraryName + " updates");
                Console.ResetColor();
                if (!await GetLibraryIfOutdated(libraryName))
                {
                    Color.White();
                    Console.WriteLine("Press any key to continue...");
                    Console.ResetColor();
                    Console.ReadKey();
                    return 1;
                }
            }

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

            Color.White(); Console.WriteLine("You have 5 seconds to read this information, GOODBYE");
            Console.ResetColor();

            Thread.Sleep(5000);

            return 0;
        }
    }
}
