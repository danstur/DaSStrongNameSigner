using System;
using System.Reflection;
using System.Security.Cryptography;

namespace DaS.StrongNameSigner
{
    internal struct PublicKeyData
    {
        public StrongNameKeyPair StrongNameKeyPair { get; }

        public byte[] PublicKeyToken { get; }

        public string PublicKeyTokenAsString { get; }

        public PublicKeyData(byte[] publicKeyPair)
        {
            StrongNameKeyPair = new StrongNameKeyPair(publicKeyPair);
            PublicKeyTokenAsString = BitConverter.ToString(StrongNameKeyPair.PublicKey)
                .Replace("-", string.Empty);
            PublicKeyToken = GetPublicKeyToken(StrongNameKeyPair.PublicKey);
        }

        private static byte[] GetPublicKeyToken(byte[] publicKey)
        {
            using (var csp = new SHA1CryptoServiceProvider())
            {
                byte[] hash = csp.ComputeHash(publicKey);

                byte[] token = new byte[8];

                for (int i = 0; i < 8; i++)
                {
                    token[i] = hash[hash.Length - i - 1];
                }
                return token;
            }
        }
    }
}