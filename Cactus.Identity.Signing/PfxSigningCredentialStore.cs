using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using IdentityServer4.Stores;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;

namespace Cactus.Identity.Signing
{
    public class PfxSigningCredentialStore : ISigningCredentialStore
    {
        private readonly string _pfxFile;
        private readonly ILogger _log;

        public PfxSigningCredentialStore(string pfxFile, ILogger log)
        {
            _pfxFile = pfxFile;
            _log = log;
        }

        public Task<SigningCredentials> GetSigningCredentialsAsync()
        {
            if (!File.Exists(_pfxFile))
            {
                _log.LogError("{file} file not found", _pfxFile);
                throw new FileNotFoundException($"Configuration error. Unable to find file {_pfxFile}");
            }

            var cert = new X509Certificate2(_pfxFile);
            if (!cert.HasPrivateKey)
            {
                throw new InvalidOperationException("X509 certificate does not have a private key.");
            }

            _log.LogDebug("Pfx loaded successfully: ", cert);
            return Task.FromResult(new SigningCredentials(new X509SecurityKey(cert), SecurityAlgorithms.RsaSha256));
        }
    }
}