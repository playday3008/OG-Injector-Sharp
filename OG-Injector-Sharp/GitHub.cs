using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.Tasks;

namespace OGInjector
{
    class GitHub
    {
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

        private static readonly HttpClient httpClient = new();

        public static async Task<bool> GetLibraryIfOutdated(string outputLibrary)
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
                    Color.DarkRed(); Console.Write("Can't connect to GitHub API. Returned code: ");
                    Color.Red(); Console.WriteLine(response.StatusCode);
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
                                Color.Yellow(); Console.Write(outputLibrary);

                                if (hash == readedAsList[1])
                                {
                                    Color.DarkYellow(); Console.WriteLine("\" was found and SHA512 checksum matched");
                                    Console.ResetColor();
                                    return true;
                                }
                            }
                            Color.DarkYellow(); Console.Write("\" was found but SHA512 checksum");
                            Color.Red(); Console.Write(" NOT ");
                            Color.DarkYellow(); Console.WriteLine("matched");
                            Console.ResetColor();
                            return true;
                        }
                        else
                        {
                            Color.DarkYellow(); Console.Write("Skipping checking for updates, because there is no connection to GitHub, but \"");
                            Color.Yellow(); Console.Write(outputLibrary);
                            Color.DarkYellow(); Console.WriteLine("\" was found");
                            Console.ResetColor();
                            return true;
                        }
                    }
                    else
                    {
                        Color.DarkYellow(); Console.Write("Skipping checking for updates, because there is no connection to GitHub, and \"");
                        Color.Yellow(); Console.Write(outputLibrary);
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
                                    Color.DarkGreen(); Console.Write("No updates for: ");
                                    Color.Green(); Console.WriteLine(outputLibrary);
                                    Color.DarkGreen(); Console.Write("SHA512 checksum matched: ");
                                    Color.Green(); Console.WriteLine(hash.Replace("-", string.Empty));
                                    Console.ResetColor();
                                    return true;
                                }
                            }
                            Color.DarkGreen(); Console.Write("No updates for: ");
                            Color.Green(); Console.WriteLine(outputLibrary);
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
                            Color.Yellow(); Console.Write(outputLibrary);
                            Color.DarkYellow(); Console.WriteLine("\" at the moment");
                            Console.ResetColor();
                            return false;
                        }
                        Color.DarkGreen(); Console.Write("Update available for: ");
                        Color.Green(); Console.WriteLine(outputLibrary);
                        Color.DarkGreen(); Console.Write("Created at: ");
                        Color.Green(); Console.WriteLine(i.CreatedAt.ToLocalTime());
                        Console.ResetColor();
                        zipUrl = i.ArchiveUrl;
                        break;
                    }
                }

                HttpResponseMessage downloadResponse = await httpClient.GetAsync(zipUrl);
                if (downloadResponse.IsSuccessStatusCode)
                {
                    Color.DarkGreen(); Console.Write("Downloading latest: ");
                    Color.Green(); Console.WriteLine(outputLibrary);
                    Console.ResetColor();
                }
                else
                {
                    Color.DarkRed(); Console.Write("Cant download latest ");
                    Color.Red(); Console.WriteLine(outputLibrary);
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
                Program.Exception(e);
                return false;
            }

            return true;
        }
    }
}
