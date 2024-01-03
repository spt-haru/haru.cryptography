namespace Haru.Cryptography
{
    public class EftAes : BaseAes
    {
        public EftAes()
        {
            // AES-192, UTF-8 bytes, extracted from client
            Key = new byte[]
            {
                0x51, 0x6F, 0x2A, 0x6E, 0x70, 0x37, 0x2A, 0x79, 0x50, 0x48,
                0x71, 0x57, 0x58, 0x38, 0x5A, 0x42, 0x33, 0x5A, 0x4F, 0x40,
                0x6D, 0x31, 0x6B, 0x34
            };
        }
    }
}