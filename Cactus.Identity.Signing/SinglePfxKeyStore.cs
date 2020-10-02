using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using IdentityServer4;
using IdentityServer4.Configuration;
using IdentityServer4.Models;
using IdentityServer4.Stores;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;

namespace Cactus.Identity.Signing
{
    public class SinglePfxKeyStore : ISigningCredentialStore, IValidationKeysStore
    {
        private readonly string _pfxFile;
        private readonly ILogger _log;

        public SinglePfxKeyStore(string pfxFile, ILogger log)
        {
            _pfxFile = pfxFile;
            _log = log;
        }

        public Task<SigningCredentials> GetSigningCredentialsAsync()
        {
            var cert = LoadCertificate();
            if (!cert.HasPrivateKey)
            {
                throw new InvalidOperationException("X509 certificate does not have a private key.");
            }

            _log.LogDebug("Pfx loaded successfully: ", cert);
            return Task.FromResult(new SigningCredentials(new X509SecurityKey(cert), SecurityAlgorithms.RsaSha256));
        }

        public Task<IEnumerable<SecurityKeyInfo>> GetValidationKeysAsync()
        {
            var cert = LoadCertificate();
            var res = new[]
            {
                new SecurityKeyInfo
                {
                    Key = new X509SecurityKey(cert),
                    SigningAlgorithm = SecurityAlgorithms.RsaSha256
                }
            };
            return Task.FromResult((IEnumerable<SecurityKeyInfo>) res);
        }

        private X509Certificate2 LoadCertificate()
        {
            if (File.Exists(_pfxFile)) return new X509Certificate2(_pfxFile);
            _log.LogError("{file} file not found", _pfxFile);
            throw new FileNotFoundException($"Configuration error. Unable to find file {_pfxFile}");
        }
    }
}