using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace TestProject
{
    internal class Program
    {


        static void Main(string[] args)
        {
            byte[] key = new byte[32] {
            0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
            0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88,
            0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01,
            0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe
            };

            byte[] data = Encoding.UTF8.GetBytes("Моя суперсекретная информация");
            byte[] encrypted;


            using (var kuznechik = new Kuznechik())
            using (var encryptor = kuznechik.CreateEncryptor(key, null))
            using (var ms = new MemoryStream())
            using (var cryptoStream = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
            {
                for (int i = 0; i < data.Length; i += 16)
                {
                    byte[] block = new byte[16];
                    int blockLength = Math.Min(16, data.Length - i);
                    Buffer.BlockCopy(data, i, block, 0, blockLength);
                    cryptoStream.Write(block, 0, 16);
                }
                cryptoStream.FlushFinalBlock();
                encrypted = ms.ToArray();
            }


            byte[] decrypted = new byte[encrypted.Length];

            using (var kuznechik = new Kuznechik())
            using (var decryptor = kuznechik.CreateDecryptor(key, null))
            using (var ms = new MemoryStream(encrypted))
            using (var cryptoStream = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
            {
                for (int i = 0; i < encrypted.Length; i += 16)
                    cryptoStream.ReadExactly(decrypted, i, 16);
            }

            Console.WriteLine("Encrypted: " + BitConverter.ToString(encrypted));
            Console.WriteLine("Decrypted: " + System.Text.Encoding.UTF8.GetString(decrypted));
        }
    }

    public class Kuznechik : SymmetricAlgorithm
    {
        public Kuznechik()
        {
            LegalKeySizesValue = new KeySizes[] { new KeySizes(256, 256, 0) };
            LegalBlockSizesValue = new KeySizes[] { new KeySizes(128, 128, 0) };

            KeySize = 256;
            BlockSize = 128;
            Mode = CipherMode.ECB;
            Padding = PaddingMode.Zeros;
        }

        public override ICryptoTransform CreateDecryptor(byte[] rgbKey, byte[]? rgbIV)
        {
            return new KuznechikTransform(rgbKey, false);
        }

        public override ICryptoTransform CreateEncryptor(byte[] rgbKey, byte[]? rgbIV)
        {
            return new KuznechikTransform(rgbKey, true);
        }

        public override void GenerateIV()
        {
            IV = new byte[32];
        }

        public override void GenerateKey()
        {
            Key = new byte[16];
        }

        class KuznechikInterop
        {
            private const string DllName = "Kuznechik.dll";

            [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
            public static extern void InitKey(byte[] key);

            [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
            public static extern void EncryptBlock(byte[] input, byte[] output);

            [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
            public static extern void DecryptBlock(byte[] input, byte[] output);
        }

        class KuznechikTransform : ICryptoTransform
        {
            private readonly bool _encrypt;
            public KuznechikTransform(byte[] key, bool encrypt)
            {
                KuznechikInterop.InitKey(key);
                _encrypt = encrypt;
            }

            const int BLOCK_SIZE = 16;
            public bool CanReuseTransform => false;

            public bool CanTransformMultipleBlocks => true;

            public int InputBlockSize => BLOCK_SIZE;

            public int OutputBlockSize => BLOCK_SIZE;

            public void Dispose()
            {

            }

            public int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
            {
                if (inputCount != 16)
                    throw new ArgumentException("Block size must be 16 bytes");
                byte[] block = new byte[16];
                Buffer.BlockCopy(inputBuffer, inputOffset, block, 0, 16);

                byte[] output = new byte[16];

                if (_encrypt)
                    KuznechikInterop.EncryptBlock(block, output);
                else
                    KuznechikInterop.DecryptBlock(block, output);

                Buffer.BlockCopy(output, 0, outputBuffer, outputOffset, 16);
                return 16; // Всегда обрабатываем один блок
            }

            public byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
            {
                byte[] block = new byte[16];
                Buffer.BlockCopy(inputBuffer, inputOffset, block, 0, inputCount);
                byte[] output = new byte[16];
                if (_encrypt)
                    KuznechikInterop.EncryptBlock(block, output);
                else
                    KuznechikInterop.DecryptBlock(block, output);

                return output;
            }
        }

    }
}
