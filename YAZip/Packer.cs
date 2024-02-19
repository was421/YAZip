using Newtonsoft.Json;
using SoulsFormats;
using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Hashing;
using System.IO.MemoryMappedFiles;
using System.Collections.Concurrent;
using System.Threading.Tasks;
using System.Linq;
using System.Text;
using System.Data.SQLite;

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
            string databaseFileName = "patches.db3";
            string databasePath = Path.Combine(Directory.GetCurrentDirectory(), databaseFileName);

            // Check if the database file exists
            if (!File.Exists(databasePath))
            {
                // If the database file doesn't exist, create it
                SQLiteConnection.CreateFile(databasePath);
                Console.WriteLine($"Database '{databaseFileName}' created successfully!");
            }

            string connectionString = $"Data Source={databasePath};";
            var db  = new SQLiteConnection(connectionString);
            db.Open();
            var globalTableStatement =
                "CREATE TABLE IF NOT EXISTS \"global\"(" +
                "\"id\" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT UNIQUE,"+
                "\"layer\" INTEGER NOT NULL DEFAULT 0 )";
            var globalTableCommand = new SQLiteCommand(globalTableStatement, db);
            globalTableCommand.ExecuteReader();

            int patchLayer = 0;
            var getLayerCommand = new SQLiteCommand("SELECT layer FROM \"global\" LIMIT 1", db);
            var queryResults = getLayerCommand.ExecuteReader();
            if (queryResults.Read())
            {
                patchLayer = queryResults.GetInt32(0) + 1;
                var updateGlobal = new SQLiteCommand($"UPDATE \"global\" SET layer = {patchLayer} WHERE id = 0;", db);
                updateGlobal.ExecuteReader();
            }
            else
            {
                var populateGlobal = new SQLiteCommand("INSERT INTO \"global\" VALUES(0,0)", db);
                populateGlobal.ExecuteReader();
            }

            var patchTableStatement =
                "CREATE TABLE IF NOT EXISTS \"patch\" (" +
                "\"id\"    INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT UNIQUE," +
                "\"fileNameHash\"  INTEGER NOT NULL," +
                "\"fileName\"  TEXT NOT NULL," +
                "\"layer\" INTEGER NOT NULL," +
                "\"fileHash\"  INTEGER NOT NULL)";
            var patchTableCommand = new SQLiteCommand(patchTableStatement, db);
            patchTableCommand.ExecuteReader();

            List<int> hashes = new List<int>();
            var bhdWriter = new BHD5(BHD5.Game.DarkSouls3);
            bhdWriter.Unk05 = true;
            bhdWriter.Salt = "FDP_YAZip";
            var fileList = new List<string>();
            var fileDir = Directory.GetParent(filePath);
            var fileName = filePath.Replace($"{fileDir}\\", "");
            var BhdBdtPairName = fileName;
            if(patchLayer != 0)
            {
                BhdBdtPairName = $"{BhdBdtPairName}_patch_{patchLayer.ToString("00")}";
            }

            string pathBDT = $@"{writePath}\{BhdBdtPairName}.bdt";
            string pathBHD = $@"{writePath}\{BhdBdtPairName}.bhd";

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
            if (File.Exists(pathBHD))
                File.Delete(pathBHD);


            string[] files;
            var folders = Directory.GetDirectories(filePath);
            string[] excludedFolders = { "sound", "movie", "yarr", "DRAG CONTENTS INTO GAME FOLDER" };
            string[] pendingFileList = Directory.GetFiles(filePath, "*", SearchOption.TopDirectoryOnly);
            foreach (var folder in folders)
            {
                files = Directory.GetFiles(folder, "*", SearchOption.AllDirectories);
                pendingFileList = pendingFileList.Concat(files).ToArray();

            }
            ConcurrentBag<(string,uint)> masterFileList = new ConcurrentBag<(string, uint)>();
            Parallel.ForEach(pendingFileList, (file) =>  
            {
                string folderName = Path.GetDirectoryName(file).ToLower();
                if (excludedFolders.Any(folder => folderName.Contains(folder.ToLower())))
                {
                    return;
                }
                try
                {
                    var mmf = MemoryMappedFile.CreateFromFile(file);
                    var mmfStream = mmf.CreateViewStream();

                    var crc32Hash = new Crc32();
                    crc32Hash.Append(mmfStream);
                    var FileHash = crc32Hash.GetCurrentHashAsUInt32();

                    mmfStream.Close();
                    mmf.Dispose();

                    masterFileList.Add((file, FileHash));
                }catch(Exception e)
                {
                    Console.WriteLine($"MMFile:{file}: Is Probs Zero");
                    masterFileList.Add((file, 0));
                }
            });

            int fileCount = masterFileList.Count;

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
            
            BHD5.Bucket[] buckets = new BHD5.Bucket[prime];
            for (int i = 0; i < buckets.Length; i++)
            {
                buckets[i] = new BHD5.Bucket();
            }
            var currentFile = 0;
            using (FileStream bhdStream = File.Create(pathBHD))
            using (var bdtStream = new FileStream(pathBDT, FileMode.Append))
            {
                foreach (var pair in masterFileList)
                {
                    var file = pair.Item1;
                    var FileHash = pair.Item2;

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
                    var FileNameHash = SFUtil.FromPathHash(hashPath);
                    var headerHash = ChecksumUtil.ComputeHash(hashPath);
                    

                    /*
                     * SQLITE CHECK
                     */

                    bool skipFile = false;
                    var checkStatement = $"SELECT fileHash FROM \"patch\" WHERE fileNameHash = {(int)FileNameHash} ORDER BY layer DESC";
                    Console.WriteLine(checkStatement);
                    var checkCommand = new SQLiteCommand(checkStatement, db);
                    var checkCommandResults = checkCommand.ExecuteReader();
                    if (checkCommandResults.Read())
                    {
                        Console.WriteLine($"{FileHash} = {(uint)checkCommandResults.GetInt32(0)}");
                        skipFile = (FileHash == (uint)checkCommandResults.GetInt32(0));
                    }

                    if (skipFile)
                    {
                        progress.Report((((double)(currentFile) / fileCount),$"{hashPath} is unchanged, skipping..."));
                        continue;
                    }

                    var insertCommand = $"INSERT INTO \"patch\" (fileNameHash,fileName,layer,fileHash) VALUES ({(int)FileNameHash},\"{hashPath}\",{patchLayer},{(int)FileHash})";

                    var includedFileCommand = new SQLiteCommand(insertCommand, db);
                    includedFileCommand.ExecuteReader();

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
                    header.FileNameHash = FileNameHash;
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

            db.Close();

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