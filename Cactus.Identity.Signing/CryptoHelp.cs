using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Cactus.Identity.Signing
{
    internal static class CryptoHelp
	{
		public static X509Certificate2 LoadPem(string certFile, string keyFile)
		{
			_ = certFile ?? throw new ArgumentNullException(nameof(certFile));
			_ = keyFile ?? throw new ArgumentNullException(nameof(keyFile));

			if (!File.Exists(certFile)) throw new ArgumentException(nameof(certFile));
			if (!File.Exists(keyFile)) throw new ArgumentException(nameof(keyFile));

			var pubCert = File.ReadAllText(certFile);
			var pubCertBytes = GetBytesFromPem(pubCert, PemStringType.Certificate);

			var privKey = File.ReadAllText(keyFile);
			var privKeyBytes = GetBytesFromPem(privKey, PemStringType.RsaPrivateKey);

			var cert = new X509Certificate2(pubCertBytes);
			var rsa = RSA.Create();
			rsa.ImportRSAPrivateKey(privKeyBytes, out _);
			var res = cert.CopyWithPrivateKey(rsa);
			return res;
		}

		/// <summary>
		/// 
		/// </summary>
		/// <param name="pemString"></param>
		/// <param name="type"></param>
		/// <returns></returns>
		private static byte[] GetBytesFromPem(string pemString, PemStringType type)
		{
			string header;
			string footer;

			switch (type)
			{
				case PemStringType.Certificate:
					header = "-----BEGIN CERTIFICATE-----";
					footer = "-----END CERTIFICATE-----";
					break;
				case PemStringType.RsaPrivateKey:
					header = "-----BEGIN RSA PRIVATE KEY-----";
					footer = "-----END RSA PRIVATE KEY-----";
					break;
				default:
					return null;
			}

			int start = pemString.IndexOf(header, StringComparison.Ordinal) + header.Length;
			int end = pemString.IndexOf(footer, start, StringComparison.Ordinal) - start;
			return Convert.FromBase64String(pemString.Substring(start, end));
		}

		private enum PemStringType
		{
			Certificate,
			RsaPrivateKey
		}
	}
}