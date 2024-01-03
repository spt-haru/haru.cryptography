using System;

namespace Haru.Cryptography
{
    public abstract class BaseXor
    {
        protected byte Key;

        private ReadOnlySpan<byte> Run(ReadOnlySpan<byte> data)
        {
            Span<byte> bytes = data.ToArray();

            for (var i = 0; i < bytes.Length; ++i)
            {
                bytes[i] ^= Key;
            }

            return bytes;
        }

        public ReadOnlySpan<byte> Decrypt(ReadOnlySpan<byte> data)
        {      
            return Run(data);
        }

        public ReadOnlySpan<byte> Encrypt(ReadOnlySpan<byte> data)
        {
            return Run(data);
        }
    }
}