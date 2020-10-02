using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using IdentityServer4.Models;
using IdentityServer4.Stores;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;

namespace Cactus.Identity.Signing
{
    public class CertManagerKeyStore : ISigningCredentialStore, IValidationKeysStore
    {
        public const string CrtDefaultName = "tls.crt";
        public const string KeyDefaultName = "tls.key";
        public const string KeystoreDefaultName = "keystore.p12";
        private readonly string _crtFile;
        private readonly string _keyFile;
        private readonly string _keystoreFile;
        private readonly string _keyStorePassword;
        private readonly ILogger _log;

        public CertManagerKeyStore(string folder, string keyStorePassword, ILogger log) : this(
            Path.Combine(folder, CrtDefaultName),
            Path.Combine(folder, KeyDefaultName),
            Path.Combine(folder, KeystoreDefaultName),
            keyStorePassword,
            log)
        {
        }

        public CertManagerKeyStore(string crtFile, string keyFile, string keystoreFile, string keyStorePassword,
            ILogger log)
        {
            _crtFile = crtFile;
            _keyFile = keyFile;
            _keystoreFile = keystoreFile;
            _keyStorePassword = keyStorePassword;
            _log = log;
        }

        public Task<SigningCredentials> GetSigningCredentialsAsync()
        {
            var cert = LoadSigningCertificate();
            if (!cert.HasPrivateKey)
            {
                throw new InvalidOperationException("X509 certificate does not have a private key.");
            }

            _log.LogDebug("PEM loaded successfully: ", cert);
            return Task.FromResult(new SigningCredentials(new X509SecurityKey(cert), SecurityAlgorithms.RsaSha256));
        }

        public Task<IEnumerable<SecurityKeyInfo>> GetValidationKeysAsync()
        {
            var res = new List<SecurityKeyInfo>();
            var cert = LoadSigningCertificate();
            res.Add(new SecurityKeyInfo
            {
                Key = new X509SecurityKey(cert),
                SigningAlgorithm = SecurityAlgorithms.RsaSha256
            });
            res.AddRange(LoadKeystore());
            return Task.FromResult((IEnumerable<SecurityKeyInfo>) res);
        }

        private X509Certificate2 LoadSigningCertificate()
        {
            if (!File.Exists(_crtFile))
            {
                _log.LogError("{file} file not found", _crtFile);
                throw new FileNotFoundException($"Configuration error. Unable to find file {_crtFile}");
            }

            if (!File.Exists(_keyFile))
            {
                _log.LogError("{file} file not found", _keyFile);
                throw new FileNotFoundException($"Configuration error. Unable to find file {_keyFile}");
            }

            return CryptoHelp.LoadPem(_crtFile, _keyFile);
        }

        private IEnumerable<SecurityKeyInfo> LoadKeystore()
        {
            //Try to load keystore, if fail just return empty enumeration
            try
            {
                _log.LogDebug("Try to load keystore from {file}", _keystoreFile);
                if (!File.Exists(_keystoreFile))
                {
                    _log.LogWarning(
                        "Keystore file {file} not found, return empty collection, previously issued tokens may not be accepted",
                        _keystoreFile);
                    return Enumerable.Empty<SecurityKeyInfo>();
                }

                var keystore = Pkcs12Keystore.Load(_keystoreFile, _keyStorePassword);
                return keystore.Certificates
                    .Where(e => e.Issuer != e.Subject) //skip self-signed CA
                    .Select(e => new SecurityKeyInfo
                    {
                        Key = new X509SecurityKey(e),
                        SigningAlgorithm = SecurityAlgorithms.RsaSha256
                    });
            }
            catch (Exception ex)
            {
                _log.LogError(
                    "Fail to load keystore, return empty collection, previously issued tokens may not be accepted: {ex}",
                    ex);
                return Enumerable.Empty<SecurityKeyInfo>();
            }
        }
    }
}