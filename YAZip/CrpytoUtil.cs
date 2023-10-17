using SoulsFormats;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Engines;

namespace YAZip
{
    class CryptoUtil
    {
        private static AesCryptoServiceProvider AESC = new AesCryptoServiceProvider() { Mode = CipherMode.CBC, Padding = PaddingMode.PKCS7 };

        private class PasswordFinder : IPasswordFinder
        {
            private string password;

            public PasswordFinder(string password)
            {
                this.password = password;
            }

            public char[] GetPassword()
            {
                return password.ToCharArray();
            }
        }
        private static AsymmetricKeyParameter LoadPrivateKey(string privateKeyFile, string privateKeyPassword)
        {
            // Read the private key from the file
            using (StreamReader reader = new StreamReader(privateKeyFile))
            {
                PemReader pemReader = new PemReader(reader, new PasswordFinder(privateKeyPassword));
                AsymmetricCipherKeyPair keyPair = (AsymmetricCipherKeyPair)pemReader.ReadObject();
                return keyPair.Private;
            }
        }
        private static AsymmetricKeyParameter LoadPublicKey(string publicKeyFile)
        {
            string key = File.ReadAllText(publicKeyFile);
            PemReader pemReader = new PemReader(new StringReader(key));
            return (AsymmetricKeyParameter)pemReader.ReadObject();
        }
            /// <summary>
            /// Encrypt BHD with password
            /// </summary>
            /// <param name="bhdPath"></param>
            /// <param name="keyfile"></param>
            public static void EncryptBHD_RSA(string bhdPath, string keyfile)
        {
            // Load the private key from file
            AsymmetricKeyParameter privateKey = LoadPrivateKey(keyfile, "");
            Console.WriteLine("Loaded key");
            // Create RSA cipher and initialize it with the private key
            RsaEngine engine = new RsaEngine();
            engine.Init(true, privateKey);
            FileStream outputStream = File.Create($"{bhdPath}.enc");
            using (FileStream inputStream = File.OpenRead(bhdPath))
            {
                int inputBlockSize = engine.GetInputBlockSize();
                int outputBlockSize = engine.GetOutputBlockSize();
                byte[] inputBlock = new byte[inputBlockSize];
                while (inputStream.Read(inputBlock, 0, inputBlock.Length) > 0)
                {
                    byte[] outputBlock = engine.ProcessBlock(inputBlock, 0, inputBlockSize);

                    int requiredPadding = outputBlockSize - outputBlock.Length;
                    if (requiredPadding > 0)
                    {
                        byte[] paddedOutputBlock = new byte[outputBlockSize];
                        outputBlock.CopyTo(paddedOutputBlock, requiredPadding);
                        outputBlock = paddedOutputBlock;
                    }

                    outputStream.Write(outputBlock, 0, outputBlock.Length);
                    Console.WriteLine("write enc");
                }
            }
            outputStream.Close();
            Console.WriteLine("enc done");
        }

        /// <summary>
        /// Encrypt BHD with password
        /// </summary>
        /// <param name="bhdPath"></param>
        /// <param name="keyfile"></param>
        public static void DecryptBHD_RSA(string bhdPath, string keyfile)
        {
            // Load the private key from file
            AsymmetricKeyParameter publicKey = LoadPublicKey(keyfile);
            Console.WriteLine("Loaded key");
            // Create RSA cipher and initialize it with the private key
            RsaEngine engine = new RsaEngine();
            engine.Init(false, publicKey);
            FileStream outputStream = File.Create($"{bhdPath}.dec");
            using (FileStream inputStream = File.OpenRead(bhdPath))
            {
                int inputBlockSize = engine.GetInputBlockSize();
                int outputBlockSize = engine.GetOutputBlockSize();
                byte[] inputBlock = new byte[inputBlockSize];
                while (inputStream.Read(inputBlock, 0, inputBlock.Length) > 0)
                {
                    byte[] outputBlock = engine.ProcessBlock(inputBlock, 0, inputBlockSize);

                    int requiredPadding = outputBlockSize - outputBlock.Length;
                    if (requiredPadding > 0)
                    {
                        byte[] paddedOutputBlock = new byte[outputBlockSize];
                        outputBlock.CopyTo(paddedOutputBlock, requiredPadding);
                        outputBlock = paddedOutputBlock;
                    }

                    outputStream.Write(outputBlock, 0, outputBlock.Length);
                    Console.WriteLine("write de-enc");
                }
            }
            outputStream.Close();
            Console.WriteLine("de-enc done");
        }

        /// <summary>
        /// Encrypt BHD with password
        /// </summary>
        /// <param name="bhdPath"></param>
        /// <param name="password"></param>
        public static void EncryptBHD(string bhdPath, string password)
        {
            byte[] fileContent = File.ReadAllBytes(bhdPath);
            byte[] passwordBytes = Encoding.ASCII.GetBytes(password);
            byte[] aesKey = SHA256.Create().ComputeHash(passwordBytes);
            byte[] aesIV = MD5.Create().ComputeHash(passwordBytes);
            AESC.Key = aesKey;
            AESC.IV = aesIV;
            using (MemoryStream memoryStream = new MemoryStream())
            {
                CryptoStream cryptoStream = new CryptoStream(memoryStream, AESC.CreateEncryptor(), CryptoStreamMode.Write);

                cryptoStream.Write(fileContent, 0, fileContent.Length);
                cryptoStream.FlushFinalBlock();

                File.WriteAllBytes(bhdPath, memoryStream.ToArray());
            }
        }

        /// <summary>
        /// Decrypte password protected BHD
        /// </summary>
        /// <param name="bhdPath"></param>
        /// <param name="password"></param>
        /// <returns>MemoryStream</returns>
        public static MemoryStream DecryptBHD(string bhdPath, string password)
        {
            byte[] fileContent = File.ReadAllBytes(bhdPath);
            byte[] passwordBytes = Encoding.ASCII.GetBytes(password);
            byte[] aesKey = SHA256.Create().ComputeHash(passwordBytes);
            byte[] aesIV = MD5.Create().ComputeHash(passwordBytes);
            AESC.Key = aesKey;
            AESC.IV = aesIV;
            MemoryStream memoryStream = new MemoryStream();

            CryptoStream cryptoStream = new CryptoStream(memoryStream, AESC.CreateDecryptor(), CryptoStreamMode.Write);

            cryptoStream.Write(fileContent, 0, fileContent.Length);
            cryptoStream.FlushFinalBlock();

            memoryStream.Seek(0, SeekOrigin.Begin);
            return memoryStream;

        }

        private static AesManaged AES = new AesManaged() { Mode = CipherMode.ECB, Padding = PaddingMode.None, KeySize = 128 };

        /// <summary>
        /// Generate AES key
        /// </summary>
        /// <returns>byte[] AES Key</returns>
        public static byte[] GetKey()
        {
            AES.GenerateKey();
            return AES.Key;
        }

        /// <summary>
        /// Get ranges for bdt files based on length and if flagged for fullEncrypt, sends off for encryption
        /// </summary>
        /// <param name="data"></param>
        /// <param name="key"></param>
        /// <param name="fullEncrypt"></param>
        /// <returns>List of BHD5.Range</returns>
        public static List<BHD5.Range> Encrypt(byte[] data, byte[] key, bool fullEncrypt)
        {
            if (data.Length < 128)
            {
                fullEncrypt = true;
            }

            var ranges = new List<BHD5.Range>();

            ranges.Add(new BHD5.Range(-1, -1));
            if (fullEncrypt)
            {
                int output = ((data.Length / 16) - 1) * 16;
                if (output == 0 || output == -16)
                    return ranges;

                ranges[0] = new BHD5.Range(0, output);
                EncryptData(data, key, ranges);
                return ranges;
            }

            
            ranges.Add(new BHD5.Range(-1, -1));
            ranges.Add(new BHD5.Range(-1, -1));
            var rand = new Random();

            if (data.Length > 128)
            {
                ranges[0] = new BHD5.Range(0, 128);

                if (data.Length > 1056)
                {
                    ranges[1] = new BHD5.Range(1024, 1056);

                    if (data.Length > 102864)
                    {
                        ranges[2] = new BHD5.Range(102400, 102864);
                    }
                }

            }



            EncryptData(data, key, ranges);
            return ranges;
        }

        /// <summary>
        /// Encrypt ranges
        /// </summary>
        /// <param name="data"></param>
        /// <param name="key"></param>
        /// <param name="ranges"></param>
        private static void EncryptData(byte[] data, byte[] key, List<BHD5.Range> ranges)
        {
            using (ICryptoTransform encryptor = AES.CreateEncryptor(key, new byte[16]))
            {
                foreach (BHD5.Range range in ranges.Where(r => r.StartOffset != -1 && r.EndOffset != -1 && r.StartOffset != r.EndOffset))
                {
                    int start = (int)range.StartOffset;
                    int count = (int)(range.EndOffset - range.StartOffset);
                    encryptor.TransformBlock(data, start, count, data, start);
                }
            }
        }

        public static AsymmetricKeyParameter GetKeyOrDefault(string key)
        {
            try
            {
                PemReader pemReader = new PemReader(new StringReader(key));
                return (AsymmetricKeyParameter)pemReader.ReadObject();
            }
            catch
            {
                return null;
            }
        }

        public static byte[] HashWithSalt(byte[] data, byte[] salt)
        {
            using (var sha256 = new SHA256Managed())
            {
                // Concatenate the data and salt
                byte[] dataWithSalt = new byte[data.Length + salt.Length];
                Array.Copy(data, dataWithSalt, data.Length);
                Array.Copy(salt, 0, dataWithSalt, data.Length, salt.Length);

                // Compute the hash
                byte[] hashBytes = sha256.ComputeHash(dataWithSalt);

                return hashBytes;
            }
        }
    }
}
