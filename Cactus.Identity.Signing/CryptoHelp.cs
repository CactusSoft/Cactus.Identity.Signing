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
			var pubCertBytes = GetBytesFromPEM(pubCert, PemStringType.Certificate);

			var privKey = File.ReadAllText(keyFile);
			var privKeyBytes = GetBytesFromPEM(privKey, PemStringType.RsaPrivateKey);

			var cert = new X509Certificate2(pubCertBytes);
			var rsa = RSA.Create();
			rsa.ImportRSAPrivateKey(privKeyBytes, out _);
			var res = cert.CopyWithPrivateKey(rsa);
			return res;
		}

		/// <summary>
		/// This helper function parses an integer size from the reader using the ASN.1 format
		/// </summary>
		/// <param name="rd"></param>
		/// <returns></returns>
		public static int DecodeIntegerSize(BinaryReader rd)
		{
			int count;

			var byteValue = rd.ReadByte();
			if (byteValue != 0x02) // indicates an ASN.1 integer value follows
				return 0;

			byteValue = rd.ReadByte();
			if (byteValue == 0x81)
			{
				count = rd.ReadByte(); // data size is the following byte
			}
			else if (byteValue == 0x82)
			{
				byte hi = rd.ReadByte(); // data size in next 2 bytes
				byte lo = rd.ReadByte();
				count = BitConverter.ToUInt16(new[] {lo, hi}, 0);
			}
			else
			{
				count = byteValue; // we already have the data size
			}

			//remove high order zeros in data
			while (rd.ReadByte() == 0x00)
			{
				count -= 1;
			}

			rd.BaseStream.Seek(-1, SeekOrigin.Current);

			return count;
		}

		/// <summary>
		/// 
		/// </summary>
		/// <param name="pemString"></param>
		/// <param name="type"></param>
		/// <returns></returns>
		public static byte[] GetBytesFromPEM(string pemString, PemStringType type)
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

		/// <summary>
		/// 
		/// </summary>
		/// <param name="inputBytes"></param>
		/// <param name="alignSize"></param>
		/// <returns></returns>
		public static byte[] AlignBytes(byte[] inputBytes, int alignSize)
		{
			int inputBytesSize = inputBytes.Length;

			if ((alignSize != -1) && (inputBytesSize < alignSize))
			{
				byte[] buf = new byte[alignSize];
				for (int i = 0; i < inputBytesSize; ++i)
				{
					buf[i + (alignSize - inputBytesSize)] = inputBytes[i];
				}

				return buf;
			}
			else
			{
				return inputBytes; // Already aligned, or doesn't need alignment
			}
		}

		public enum PemStringType
		{
			Certificate,
			RsaPrivateKey
		}
	}
}