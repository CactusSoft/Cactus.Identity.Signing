using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using IdentityServer4.Models;
using IdentityServer4.Stores;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;

namespace Cactus.Identity.Signing
{
    public class Pkcs12ValidationKeysStore : IValidationKeysStore
    {
        public const string KeystoreDefaultName = "keystore.p12";
        private readonly ILogger _log;
        private readonly string _keyStoreFile;
        private readonly string _password;

        public Pkcs12ValidationKeysStore(string keyStoreFile, string password, ILogger log)
        {
            _keyStoreFile = keyStoreFile;
            _password = password;
            _log = log;
        }

        public Task<IEnumerable<SecurityKeyInfo>> GetValidationKeysAsync()
        {
            //Try to load keystore
            try
            {
                _log.LogDebug("Try to load keystore from {file}", _keyStoreFile);
                if (!File.Exists(_keyStoreFile))
                {
                    _log.LogWarning(
                        "Keystore file {file} not found, return empty collection, previously issued tokens may not be accepted",
                        _keyStoreFile);
                    return Task.FromResult(Enumerable.Empty<SecurityKeyInfo>());
                }

                var keystore = Pkcs12Keystore.Load(_keyStoreFile, _password);
                var res = keystore.Certificates
                    .Where(e => e.Issuer != e.Subject) //skip self-signed CA
                    .Select(e => new SecurityKeyInfo
                    {
                        Key = new X509SecurityKey(e),
                        SigningAlgorithm = SecurityAlgorithms.RsaSha256
                    });

                return Task.FromResult(res);
            }
            catch (Exception ex)
            {
                _log.LogError("Fail to load keystore, return empty collection, previously issued tokens may not be accepted: {ex}", ex);
                return Task.FromResult(Enumerable.Empty<SecurityKeyInfo>());
            }
        }
    }
}