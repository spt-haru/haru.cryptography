using System;
using System.IO;
using System.Security.Cryptography;

namespace Haru.Cryptography
{
    // CryptoStream in write mode flushes the underlying stream. In
    // netstandard2.1 the constructor provides leaveOpen but not on
    // netstandard2.0. Using reflection to set _leaveOpen to true would be
    // slower than not using MemoryStreamPool, so here we are.
    // -- Senko-san, 2023-11-17

    public abstract class BaseAes
    {
        // AES blocksize is always 128 bits
        private const int _blockSize = 16;
        protected byte[] Key;

        private ReadOnlySpan<byte> Run(ReadOnlySpan<byte> data, bool encrypt)
        {
            using (var aes = Aes.Create())
            {
                using (var ms = new MemoryStream())
                {
                    aes.Key = Key;

                    var bytes = data.ToArray();
                    var offset = 0;

                    if (encrypt)
                    {
                        // encrypting: write first block as IV
                        aes.GenerateIV();
                        ms.Write(aes.IV, 0, aes.IV.Length);
                    }
                    else
                    {
                        // decrypting: read first block as IV
                        var iv = new ReadOnlySpan<byte>(bytes, 0, _blockSize);
                        aes.IV = iv.ToArray();
                        offset = _blockSize;
                    }

                    // set cipher
                    var transform = encrypt
                        ? aes.CreateEncryptor()
                        : aes.CreateDecryptor();

                    // get data
                    using (var cs = new CryptoStream(ms, transform, CryptoStreamMode.Write))
                    {
                        cs.Write(bytes, offset, data.Length - offset);
                    }

                    return ms.ToArray();
                }
            }
        }

        public ReadOnlySpan<byte> Decrypt(ReadOnlySpan<byte> data)
        {      
            return Run(data, false);
        }

        public ReadOnlySpan<byte> Encrypt(ReadOnlySpan<byte> data)
        {
            return Run(data, true);
        }
    }
}