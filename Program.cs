using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;

namespace file_string_extractor
{
    internal class Program
    {
        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_DOS_HEADER
        {
            public ushort e_magic;
            public ushort e_cblp;
            public ushort e_cp;
            public ushort e_crlc;
            public ushort e_cparhdr;
            public ushort e_minalloc;
            public ushort e_maxalloc;
            public ushort e_ss;
            public ushort e_sp;
            public ushort e_csum;
            public ushort e_ip;
            public ushort e_cs;
            public ushort e_lfarlc;
            public ushort e_ovno;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
            public ushort[] e_res1;

            public ushort e_oemid;
            public ushort e_oeminfo;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 10)]
            public ushort[] e_res2;

            public int e_lfanew;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_FILE_HEADER
        {
            public ushort Machine;
            public ushort NumberOfSections;
            public uint TimeDateStamp;
            public uint PointerToSymbolTable;
            public uint NumberOfSymbols;
            public ushort SizeOfOptionalHeader;
            public ushort Characteristics;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_OPTIONAL_HEADER32
        {
            public ushort Magic;
            public byte MajorLinkerVersion;
            public byte MinorLinkerVersion;
            public uint SizeOfCode;
            public uint SizeOfInitializedData;
            public uint SizeOfUninitializedData;
            public uint AddressOfEntryPoint;
            public uint BaseOfCode;
            public uint BaseOfData;
            public uint ImageBase;
            public uint SectionAlignment;
            public uint FileAlignment;
            public ushort MajorOperatingSystemVersion;
            public ushort MinorOperatingSystemVersion;
            public ushort MajorImageVersion;
            public ushort MinorImageVersion;
            public ushort MajorSubsystemVersion;
            public ushort MinorSubsystemVersion;
            public uint Win32VersionValue;
            public uint SizeOfImage;
            public uint SizeOfHeaders;
            public uint CheckSum;
            public ushort Subsystem;
            public ushort DllCharacteristics;
            public uint SizeOfStackReserve;
            public uint SizeOfStackCommit;
            public uint SizeOfHeapReserve;
            public uint SizeOfHeapCommit;
            public uint LoaderFlags;
            public uint NumberOfRvaAndSizes;
        }

        public struct IMAGE_NT_HEADERS32
        {
            public uint Signature;
            public IMAGE_FILE_HEADER FileHeader;
            public IMAGE_OPTIONAL_HEADER32 OptionalHeader;
        }

        private static void Main(string[] args)
        {
            if (args.Length > 0)
            {
                string file = args[0];

                if (file != null)
                {
                    FileInfo fileInfo = new FileInfo(file);

                    string text = $"File Name: {fileInfo.Name}\nMD5: {GetMD5Hash(file)}\nSHA 256: {GetSha256Hash(file)}\nPcaSvc: 0x{GetPcaSvcFileString(file)[0]}\nDPS: !{GetPcaSvcFileString(file)[1]}\nFile Size: {fileInfo.Length}";

                    WriteTxtFile($"{fileInfo.Name}.txt", text);
                    WriteTxtFile($"{fileInfo.Name}.txt", text);

                    Console.WriteLine("Done, strings extracted");

                    Thread.Sleep(3000);

                    Environment.Exit(0);
                }
            }
        }

        private static List<string> GetPcaSvcFileString(string fileDir)
        {
            List<string> pEHeadersFileStringList = new List<string>();

            using (FileStream fs = new FileStream(fileDir, FileMode.Open, FileAccess.Read))
            using (BinaryReader reader = new BinaryReader(fs))
            {
                IMAGE_DOS_HEADER dosHeader = FromBinaryReader<IMAGE_DOS_HEADER>(reader);

                if (dosHeader.e_magic != 0x5A4D)
                {
                    Console.WriteLine("Invalid pe file");
                }
                reader.BaseStream.Seek(dosHeader.e_lfanew, SeekOrigin.Begin);
                IMAGE_NT_HEADERS32 ntHeaders = FromBinaryReader<IMAGE_NT_HEADERS32>(reader);

                if (ntHeaders.Signature != 0x00004550)
                {
                    Console.WriteLine("Invalid pe file");
                }


                uint timeDateStamp = ntHeaders.FileHeader.TimeDateStamp;
                DateTimeOffset dateTimeOffset = DateTimeOffset.FromUnixTimeSeconds(timeDateStamp);
                string formattedTimestamp = dateTimeOffset.ToString("yyyy/MM/dd:HH:mm:ss");

                pEHeadersFileStringList.Add(ntHeaders.OptionalHeader.SizeOfImage.ToString("X").ToLowerInvariant());

                pEHeadersFileStringList.Add(formattedTimestamp);

                return pEHeadersFileStringList;
            }
        }

        private static T FromBinaryReader<T>(BinaryReader reader)
        {
            byte[] bytes = reader.ReadBytes(Marshal.SizeOf(typeof(T)));
            GCHandle handle = GCHandle.Alloc(bytes, GCHandleType.Pinned);
            T theStructure = (T)Marshal.PtrToStructure(handle.AddrOfPinnedObject(), typeof(T));
            handle.Free();
            return theStructure;
        }

        private static string GetMD5Hash(string fileDir)
        {
            using (FileStream stream = File.OpenRead(fileDir))
            {
                using (var md5 = MD5.Create())
                {
                    byte[] bytes = md5.ComputeHash(stream);

                    return BitConverter.ToString(bytes).Replace("-", "").ToLowerInvariant();
                }
            }
        }

        private static string GetSha256Hash(string fileDir)
        {
            using (FileStream stream = File.OpenRead(fileDir))
            {
                using (var sha = SHA256.Create())
                {
                    byte[] bytes = sha.ComputeHash(stream);

                    return BitConverter.ToString(bytes).Replace("-", "").ToLowerInvariant();
                }
            }
        }

        private static string StringToHex(string input)
        {
            char[] chars = input.ToCharArray();
            StringBuilder hex = new StringBuilder(chars.Length * 2);

            foreach (char c in chars)
            {
                hex.AppendFormat("{0:X2}", (int)c);
            }

            return hex.ToString();
        }

        private static void WriteTxtFile(string destFile, string tx)
        {
            try
            {
                byte[] tBytes = Encoding.UTF8.GetBytes(tx);

                File.WriteAllBytes(destFile, tBytes);
            }
            catch
            {
                throw new Exception("Error to write file");
            }
        }
    }
}