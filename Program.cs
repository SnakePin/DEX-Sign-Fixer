using System;
using System.IO;
using System.Security.Cryptography;

namespace DexSignFixer
{
    class Program
    {
        private static uint CalcAdler32(byte[] arr, int offset)
        {
            const int mod = 65521;
            uint a = 1, b = 0;

            for (int i = offset; i < arr.Length; i++)
            {
                byte c = arr[i];
                a = (a + c) % mod;
                b = (b + a) % mod;
            }

            return (b << 16) | a;
        }
        private static byte[] CalcSha1_160bit(byte[] arr, int offset)
        {
            using (SHA1 sha = new SHA1CryptoServiceProvider())
            {
                return sha.ComputeHash(arr, offset, arr.Length - offset);
            }
        }

        private static readonly byte[] DEX_FILE_MAGIC_UNIVERSAL = { 0x64, 0x65, 0x78/*, 0x0a, 0x30, 0x33*/ };

        private const int DEX_SIGNATURE_OFFSET = 12;
        private const int DEX_SIGNATURE_END_OFFSET = 32;

        private const int DEX_CHECKSUM_OFFSET = 8;
        private const int DEX_CHECKSUM_END_OFFSET = 12;

        static void PrintHelp()
        {
            string currentExecutableFileName = Path.GetFileName(System.Reflection.Assembly.GetEntryAssembly().Location);

            Console.WriteLine($"Usage: {currentExecutableFileName} inputFilePath");
            return;
        }

        static void Main(string[] args)
        {
            Console.WriteLine("Dex Signature/Checksum Fixer");

            if (args.Length != 1)
            {
                PrintHelp();
                return;
            }

            string inputFilePath = args[0];

            if (!File.Exists(inputFilePath))
            {
                Console.WriteLine("Input file does not exist! See usage by not passing any arguments.");
                return;
            }

            Console.WriteLine("Reading input file...");
            byte[] fileBytes = File.ReadAllBytes(inputFilePath);
            Console.WriteLine("Done!");

            for (int i = 0; i < DEX_FILE_MAGIC_UNIVERSAL.Length; i++)
            {
                if (fileBytes[i] != DEX_FILE_MAGIC_UNIVERSAL[i])
                {
                    Console.WriteLine("Input file is not a dex file! See usage by not passing any arguments.");
                    return;
                }
            }

            bool isSignatureValid = true;
            bool isChecksumValid = true;

            Console.WriteLine("Calculating new SHA1 signature...");
            byte[] newSignature = CalcSha1_160bit(fileBytes, DEX_SIGNATURE_END_OFFSET);
            for (int i = 0; i < newSignature.Length; i++)
            {
                if (fileBytes[DEX_SIGNATURE_OFFSET + i] != newSignature[i])
                {
                    isSignatureValid = false;
                }
            }
            newSignature.CopyTo(fileBytes, DEX_SIGNATURE_OFFSET);
            Console.WriteLine("Done!");

            //Checksum must be calculated after signature has been
            Console.WriteLine("Calculating new Adler32 checksum...");
            byte[] newChecksum = BitConverter.GetBytes(CalcAdler32(fileBytes, DEX_CHECKSUM_END_OFFSET));
            for (int i = 0; i < newChecksum.Length; i++)
            {
                if (fileBytes[DEX_CHECKSUM_OFFSET + i] != newChecksum[i])
                {
                    isChecksumValid = false;
                }
            }
            newChecksum.CopyTo(fileBytes, DEX_CHECKSUM_OFFSET);
            Console.WriteLine("Done!");

            if (isSignatureValid && isChecksumValid)
            {
                Console.WriteLine("Checksum and signature are already valid for the input file, program exiting...");
                return;
            }

            string newFileNameWithoutExt = Path.GetFileNameWithoutExtension(inputFilePath) + "_headerFixed";
            string newPath = Path.Combine(Path.GetDirectoryName(inputFilePath), newFileNameWithoutExt + Path.GetExtension(inputFilePath));

            Console.WriteLine("Writing the output to " + newPath);
            File.WriteAllBytes(newPath, fileBytes);
            Console.WriteLine("Done, program exiting...");
        }
    }
}
