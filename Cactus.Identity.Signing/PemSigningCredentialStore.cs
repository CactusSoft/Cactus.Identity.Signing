using System;
using System.IO;
using System.Threading.Tasks;
using IdentityServer4.Stores;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;

namespace Cactus.Identity.Signing
{
    public class PemSigningCredentialStore : ISigningCredentialStore
    {
        public const string CrtDefaultName = "tls.crt";
        public const string KeyDefaultName = "tls.key";
        private readonly string _crtFile;
        private readonly string _keyFile;
        private readonly ILogger _log;

        public PemSigningCredentialStore(string folder, ILogger log) :
            this(Path.Combine(folder, CrtDefaultName), Path.Combine(folder, KeyDefaultName), log)
        {
        }

        public PemSigningCredentialStore(string crtFile, string keyFile, ILogger log)
        {
            _crtFile = crtFile;
            _keyFile = keyFile;
            _log = log;
        }

        public Task<SigningCredentials> GetSigningCredentialsAsync()
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

            var cert = CryptoHelp.LoadPem(_crtFile, _keyFile);
            if (!cert.HasPrivateKey)
            {
                throw new InvalidOperationException("X509 certificate does not have a private key.");
            }

            _log.LogDebug("PEM loaded successfully: ", cert);
            return Task.FromResult(new SigningCredentials(new X509SecurityKey(cert), SecurityAlgorithms.RsaSha256));
        }
    }
}