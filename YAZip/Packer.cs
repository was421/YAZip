using Newtonsoft.Json;
using SoulsFormats;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace YAZip
{
    internal class Packer
    {
        /// <summary>
        /// Packs file to bhd/bdt pair
        /// </summary>
        /// <param name="filePath"></param>
        /// <param name="writePath"></param>
        /// <param name="password"></param>
        /// <param name="progress"></param>
        /// <returns>Error string</returns>
        public static string Pack(string filePath, string writePath, string password, IProgress<(double value, string status)> progress)
        {
            List<int> hashes = new List<int>();
            var bhdWriter = new BHD5(BHD5.Game.DarkSouls3);
            bhdWriter.Unk05 = true;
            bhdWriter.Salt = "FDP_YAZip";
            var fileList = new List<string>();
            var fileDir = Directory.GetParent(filePath);
            var fileName = filePath.Replace($"{fileDir}\\", "");

            string pathBDT = $@"{writePath}\{fileName}.bdt";
            string pathBHD = $@"{writePath}\{fileName}.bhd";

            if (pathBDT.Contains(".Encrypt"))
            {
                pathBDT = pathBDT.Replace(".Encrypt", "");
                pathBHD = pathBHD.Replace(".Encrypt", "");
            }

            if (pathBDT.Contains(".DCX"))
            {
                pathBDT = pathBDT.Replace(".DCX", "");
                pathBHD = pathBHD.Replace(".DCX", "");
            }

            if (!string.IsNullOrWhiteSpace(password))
            {
                if (Settings.Instance.ds3comply)
                    CryptoUtil.EncryptBHD_RSA(pathBHD, password);
                else
                    CryptoUtil.EncryptBHD(pathBHD, password);
                return null;
            }

            if (File.Exists(pathBDT))
                File.Delete(pathBDT);

            
            var folders = Directory.GetDirectories(filePath);
            int fileCount = Directory.GetFiles(filePath, "*", SearchOption.AllDirectories).Length;
            Console.WriteLine("Finding Prime");
            bool IsPrime = false;
            int prime = fileCount;
            do
            {
                IsPrime = true;
                for (int i = 2; i < prime/2; i++)
                {
                    if(prime % i == 0)
                    {
                        IsPrime = false;
                        break;
                    }
                }
                prime--;

            } while (!IsPrime);
            prime++;
            Console.WriteLine($"Buckets:{prime}");
            string[] files;
            BHD5.Bucket[] buckets = new BHD5.Bucket[prime];
            for (int i = 0; i < buckets.Length; i++)
            {
                buckets[i] = new BHD5.Bucket();
            }
            var currentFile = 0;
            using (FileStream bhdStream = File.Create(pathBHD))
            using (var bdtStream = new FileStream(pathBDT, FileMode.Append))
            {
                string[] excludedFolders = { "sound", "movie", "yarr", "DRAG CONTENTS INTO GAME FOLDER" };
                string[] masterFileList = Directory.GetFiles(filePath, "*", SearchOption.TopDirectoryOnly);
                foreach (var folder in folders)
                {
                    files = Directory.GetFiles(folder, "*", SearchOption.AllDirectories);
                    masterFileList = masterFileList.Concat(files).ToArray();

                }
                foreach (var file in masterFileList)
                {
                    string folderName = Path.GetDirectoryName(file).ToLower();
                    if(excludedFolders.Any(folder => folderName.Contains(folder.ToLower())))
                    {
                        continue;
                    }
                    currentFile++;
                    byte[] bytes;

                    try
                    {
                        bytes = File.ReadAllBytes(file);
                    }
                    catch (IOException e)
                    {
                        return $"Cannot {Path.GetFileName(file)} write to bhd. {e.Message}";
                    }

                    var headerPath = file.Replace(fileDir.ToString(), "");
                    var hashPath = headerPath.Replace($"\\{fileName}", "").Replace("\\", "/");
                    var headerHash = ChecksumUtil.ComputeHash(hashPath);
                    var hashIndex = headerHash % buckets.Length;
                    bool compress = headerPath.Contains(".DCX");
                    if (compress)
                    {
                        bytes = DCX.Compress(bytes, DCX.Type.DCX_KRAK);
                        headerPath = headerPath.Replace(".DCX", "");
                        headerPath += ".dcx";
                    }
                    var fullEncrypt = headerPath.Contains(".Encrypt");
                    if (fullEncrypt)
                    {
                        headerPath = headerPath.Replace(".Encrypt", "");
                    }

                    fileList.Add(headerPath.Trim().Replace('\\', '/'));
                    var header = new BHD5.FileHeader();
                    //header.AESKey = new BHD5.AESKey();
                    //header.SHAHash = new BHD5.SHAHash();

                    //header.AESKey.Key = CryptoUtil.GetKey();
                    //header.AESKey.Ranges = CryptoUtil.Encrypt(bytes, header.AESKey.Key, fullEncrypt);
                    //header.AESKey.Ranges.Add((new BHD5.Range(-1, -1)));
                    //header.AESKey.Ranges.Add((new BHD5.Range(-1, -1)));
                    //header.AESKey.Ranges.Add((new BHD5.Range(-1, -1)));

                    //header.SHAHash.Hash = CryptoUtil.HashWithSalt(bytes, Encoding.UTF8.GetBytes(bhdWriter.Salt));
                    //header.SHAHash.Ranges.Add(new BHD5.Range(0, bytes.Length));
                    //header.SHAHash.Ranges.Add(new BHD5.Range(-1, -1));
                    //header.SHAHash.Ranges.Add(new BHD5.Range(-1, -1));
                    header.FileNameHash = SFUtil.FromPathHash(hashPath);
                    hashes.Add(header.FileNameHash.GetHashCode());
                    header.FileOffset = bdtStream.Length;
                    header.PaddedFileSize = bytes.Length;
                    //header.UnpaddedFileSize = bytes.Length;
                    buckets[hashIndex].Add(header);
                    progress.Report((((double)(currentFile) / fileCount),
                                $"Packing {headerPath} ({currentFile}/{fileCount}) bucket[{hashIndex}]({hashPath})[{header.FileNameHash}]..."));
                    
                    bdtStream.Write(bytes, 0, bytes.Length);
                }

                //var shuffled = bucket.OrderBy(x => Guid.NewGuid()).ToList(); //Shuffles the bucket before adding it to bhd.

                //
                foreach (var bk in buckets)
                {
                    bhdWriter.Buckets.Add(bk);
                }

                if (!Settings.Instance.ds3comply)
                    CreateJson(bhdWriter, fileList, bdtStream);
                bhdWriter.Write(bhdStream);

                bhdStream.Close();
                bdtStream.Close();
            }

            FindCollisions(hashes.ToArray());

            progress.Report(((1, $"Packing complete!")));
            return null;
        }

        /// <summary>
        /// Creates JSon bucket and adds to the end
        /// </summary>
        /// <param name="bhdWriter"></param>
        /// <param name="fileList"></param>
        /// <param name="bdtStream"></param>
        private static void CreateJson(BHD5 bhdWriter, List<string> fileList, FileStream bdtStream)
        {
            var json = JsonConvert.SerializeObject(fileList);
            var jsonBytes = Encoding.ASCII.GetBytes(json);
            var jsonBucket = new BHD5.Bucket();
            var jsonHeader = new BHD5.FileHeader();
            jsonHeader.AESKey = new BHD5.AESKey();
            jsonHeader.AESKey.Key = CryptoUtil.GetKey();
            jsonHeader.AESKey.Ranges = CryptoUtil.Encrypt(jsonBytes, jsonHeader.AESKey.Key, true);
            jsonHeader.FileNameHash = 0;
            jsonHeader.FileOffset = bdtStream.Length;
            jsonHeader.PaddedFileSize = jsonBytes.Length;
            jsonBucket.Add(jsonHeader);
            bdtStream.Write(jsonBytes, 0, jsonBytes.Length);
            bhdWriter.Buckets.Add(jsonBucket);
        }

        static void FindCollisions(int[] arr)
        {
            Console.WriteLine($"Finding Collisions");
            Dictionary<int, int> frequencyMap = new Dictionary<int, int>();

            foreach (int num in arr)
            {
                if (!frequencyMap.ContainsKey(num))
                {
                    frequencyMap[num] = 1;
                }
                else
                {
                    frequencyMap[num] += 1;
                }
            }

            foreach(var kv in frequencyMap)
            {
                if(kv.Value > 1)
                {
                    Console.WriteLine($"Hash: {kv.Key}, Count: {kv.Value}");
                }
            }
        }


    }
}