using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Haru.Cryptography;

namespace Haru.Cryptography.Tests.Units
{
    [TestClass]
    public class EftAesTest
    {
        private readonly EftAes _cipher;
        private readonly byte[] _encryptedData;
        private readonly byte[] _decryptedData;

        public EftAesTest()
        {
            _cipher = new EftAes();
            _encryptedData = new byte[]
            {
                // [0x75...0xE5, 0xC8...0xA2]: [iv, payload]
                0x75, 0x03, 0x42, 0x39, 0xDC, 0x82, 0xAD, 0x99, 0x35, 0x06,
                0x0D, 0xC8, 0x98, 0x97, 0x8E, 0xE5, 0xC8, 0x4F, 0x35, 0xD1,
                0x18, 0x2B, 0xFA, 0xC6, 0x3B, 0x47, 0x1A, 0x6E, 0x2C, 0xF9,
                0x5B, 0x5C, 0x49, 0x8F, 0x07, 0x22, 0x4D, 0x8A, 0xB2, 0x39,
                0x39, 0x94, 0x2A, 0x74, 0xBA, 0xF5, 0x4D, 0x6B, 0x25, 0x95,
                0xDC, 0xF6, 0xD0, 0xAE, 0x04, 0x87, 0x28, 0xC4, 0x86, 0x26,
                0xE5, 0x64, 0x51, 0xBF, 0xC4, 0x7A, 0xF5, 0x0E, 0x1D, 0xCB,
                0xFD, 0x0D, 0xDA, 0x09, 0x8F, 0x9C, 0x92, 0x21, 0x7F, 0xCF,
                0xD7, 0x28, 0xB7, 0xC1, 0x06, 0x88, 0xE5, 0x90, 0xD1, 0x26,
                0x25, 0x3C, 0x4A, 0x3E, 0xAC, 0xA2
            };
            _decryptedData = new byte[]
            {
                // [0x78, 0x9C, 0xAB...0xFC]: [zlib, level 6, data]
                0x78, 0x9C, 0xAB, 0x56, 0x4A, 0x2D, 0x2A, 0x52, 0xB2, 0x32,
                0xD0, 0x01, 0xD1, 0xB9, 0xC5, 0xE9, 0x4A, 0x56, 0x79, 0xA5,
                0x39, 0x39, 0x3A, 0x4A, 0x29, 0x89, 0x25, 0x89, 0x4A, 0x56,
                0xD5, 0x4A, 0xA5, 0x25, 0xC9, 0xF1, 0x25, 0x99, 0xB9, 0xA9,
                0x4A, 0x56, 0x86, 0x66, 0x96, 0x46, 0x46, 0x96, 0x06, 0x86,
                0xC6, 0x96, 0x7A, 0x86, 0x26, 0xA6, 0x86, 0xB5, 0xB5, 0x00,
                0x36, 0x12, 0x11, 0xFC
            };
        }

        [TestMethod]
        public void TestDecrypt()
        {
            var data = _cipher.Decrypt(_encryptedData);
            var result = data.SequenceEqual(_decryptedData);
            Assert.IsTrue(result);
        }

        [TestMethod]
        public void TestEncrypt()
        {
            var encrypted = _cipher.Encrypt(_decryptedData);
            var data = _cipher.Decrypt(encrypted);
            var result = data.SequenceEqual(_decryptedData);
            Assert.IsTrue(result);
        }
    }
}