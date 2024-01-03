using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Haru.Cryptography;

namespace Haru.Cryptography.Tests.Units
{
    [TestClass]
    public class EftXorTest
    {
        private readonly EftXor _cipher;
        private readonly byte[] _encryptedData;
        private readonly byte[] _decryptedData;

        public EftXorTest()
        {
            _cipher = new EftXor();
            _encryptedData = new byte[]
            {
                0x75, 0xD7
            };
            _decryptedData = new byte[]
            {
                0x78, 0xDA
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
            var data = _cipher.Encrypt(_decryptedData);
            var result = data.SequenceEqual(_encryptedData);
            Assert.IsTrue(result);
        }
    }
}