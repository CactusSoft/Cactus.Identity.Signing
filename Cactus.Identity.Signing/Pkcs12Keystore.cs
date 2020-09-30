using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;

namespace Cactus.Identity.Signing
{
    internal class Pkcs12Keystore
    {
        private readonly Pkcs12Info _info;

        public static Pkcs12Keystore Load(string file, string pass)
        {
            _ = file ?? throw new ArgumentNullException(nameof(file));
            if (!File.Exists(file)) throw new ArgumentException(nameof(file));

            using var stream = File.OpenRead(file);
            var buf = new byte[stream.Length];
            stream.Read(buf);
            var mem = new ReadOnlyMemory<byte>(buf);
            var info = Pkcs12Info.Decode(mem, out _);
            return new Pkcs12Keystore(info, pass);
        }

        public Pkcs12Keystore(Pkcs12Info info, string password)
        {
            if (!info.VerifyMac(password)) throw new ArgumentException(nameof(password));
            _info = info;
            foreach (var authSafe in info.AuthenticatedSafe.Where(e => e.ConfidentialityMode == Pkcs12ConfidentialityMode.Password))
            {
                authSafe.Decrypt(password);
            }
        }

        public IEnumerable<X509Certificate2> Certificates =>
            _info.AuthenticatedSafe
                .SelectMany(e => e.GetBags())
                .Where(e => e is Pkcs12CertBag)
                .Cast<Pkcs12CertBag>()
                .Where(e => e.IsX509Certificate)
                .Select(e => e.GetCertificate());
    }
}