using System;
using System.IO;
using System.Collections;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Net.NetworkInformation;

namespace TORComm.Utilities
{
    public static class Security
    {
        public static int GetRandomInt(int MaxInt = 0)
        {
            int ReturnValue = 0;
            Byte[] buffer = new Byte[64];
            RNGCryptoServiceProvider RNG = new RNGCryptoServiceProvider();
            RNG.GetNonZeroBytes(buffer);
            int IntermediateValue = BitConverter.ToInt32(buffer, 0);
            if (IntermediateValue < 0) { IntermediateValue *= -1; }
            if (MaxInt == 0)
            {
                ReturnValue = IntermediateValue % int.MaxValue;
            }
            else
            {
                ReturnValue = IntermediateValue % MaxInt;
            }
            return ReturnValue;
        }

        public static String HashString(String data)
        {
            String ReturnValue = String.Empty;
            if (!(String.IsNullOrEmpty(data)))
            {
                SHA512CryptoServiceProvider sha = new SHA512CryptoServiceProvider();
                ReturnValue = Convert.ToBase64String(sha.ComputeHash(System.Text.Encoding.UTF8.GetBytes(data))).Replace("=", "");
                sha.Dispose();
            }
            return ReturnValue;
        }
    }

    public static class Network
    {
        public static List<int> GetAllocatedPorts()
        {
            List<int> AssignedPorts = new List<int>();
            IPGlobalProperties properties = IPGlobalProperties.GetIPGlobalProperties();
            foreach (TcpConnectionInformation connection in properties.GetActiveTcpConnections())
            {
                AssignedPorts.Add(connection.LocalEndPoint.Port);
            }
            return AssignedPorts;
        }
        public static int GetUnusedPort(int MinPort = 49152, int MaxPort = 65535)
        {
            int port = 0;
            List<int> AssignedPorts = GetAllocatedPorts();
            while ((port < MinPort) || (port > MaxPort) || (AssignedPorts.IndexOf(port) >= 0))
            {
                port = TORComm.Utilities.Security.GetRandomInt(65535);
            }
            return port;
        }
    }

    public static class Filesystem
    {
        public static void OverwriteAndDeleteFile(String FileName, int BufferSize = 40960)
        {
            if (File.Exists(FileName))
            {
                long FileSize = 0;
                using (FileStream fstream = new FileStream(FileName, FileMode.Open, FileAccess.Write))
                {
                    FileSize = fstream.Seek(0, SeekOrigin.End);
                    fstream.Seek(0, SeekOrigin.Begin);
                    long BytesWritten = 0;
                    RNGCryptoServiceProvider RNG = new RNGCryptoServiceProvider();
                    AesCryptoServiceProvider aes = new AesCryptoServiceProvider();
                    aes.GenerateKey();
                    aes.GenerateIV();
                    using (CryptoStream cstream = new CryptoStream(fstream, aes.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        using (BinaryWriter writer = new BinaryWriter(cstream))
                        {
                            while (BytesWritten < FileSize)
                            {
                                Byte[] buffer = new Byte[BufferSize];
                                RNG.GetNonZeroBytes(buffer);
                                writer.Write(buffer);
                                BytesWritten += buffer.Length;
                            }
                        }
                    }
                }
                using (FileStream fstream = new FileStream(FileName, FileMode.Open, FileAccess.Write))
                {
                    FileSize = fstream.Seek(0, SeekOrigin.End);
                    fstream.Seek(0, SeekOrigin.Begin);
                    long BytesWritten = 0;
                    using (BinaryWriter writer = new BinaryWriter(fstream, new System.Text.UTF8Encoding(false)))
                    {
                        while (BytesWritten <= FileSize)
                        {
                            // Overwrites with following character: ☺
                            writer.Write((byte)1);
                            BytesWritten += 1;
                        }
                    }
                }
                File.Delete(FileName);
            }
        }
        public static String[] GetAllFilesInDirectory(String DirName, String[] FoundFiles = null)
        {
            ArrayList AllFiles = new ArrayList();
            if (!(FoundFiles == null))
            {
                AllFiles.AddRange(FoundFiles);
            }
            foreach (String FoundFile in Directory.GetFiles(DirName))
            {
                AllFiles.Add(FoundFile);
            }
            foreach (String FoundDir in Directory.GetDirectories(DirName))
            {
                AllFiles = new ArrayList(GetAllFilesInDirectory(FoundDir, (String[])AllFiles.ToArray(typeof(string))));
            }
            return (String[])AllFiles.ToArray(typeof(string));
        }
    }
}