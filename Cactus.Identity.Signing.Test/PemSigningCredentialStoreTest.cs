using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging.Abstractions;
using NUnit.Framework;

namespace Cactus.Identity.Signing.Test
{
    public class PemSigningCredentialStoreTest
    {
        private const string KeystorePassword = "supersecret";
        [Test]
        public async Task LoadFromFolderSuccess()
        {
            var store = new CertManagerKeyStore(".", KeystorePassword, NullLogger.Instance);
            var signingKey = await store.GetSigningCredentialsAsync();
            var validationKeys = (await store.GetValidationKeysAsync()).ToList();
            Assert.IsNotNull(signingKey);
            Assert.IsNotNull(validationKeys);
            Assert.AreEqual(2, validationKeys.Count);
            Assert.AreEqual(signingKey.Key, validationKeys.First().Key);
        }

        [Test]
        public async Task LoadFromFolderIncorrectKeystorePassword()
        {
            var store = new CertManagerKeyStore(".", "incorrect", NullLogger.Instance);
            var signingKey = await store.GetSigningCredentialsAsync();
            var validationKeys = (await store.GetValidationKeysAsync()).ToList();
            Assert.IsNotNull(signingKey);
            Assert.IsNotNull(validationKeys);
            Assert.AreEqual(1, validationKeys.Count, "No validation keys from keystore should be loaded");
            Assert.AreEqual(signingKey.Key, validationKeys.First().Key);
        }

        [Test]
        public async Task LoadFromFilesSuccess()
        {
            var store = new CertManagerKeyStore(
                CertManagerKeyStore.CrtDefaultName,
                CertManagerKeyStore.KeyDefaultName,
                CertManagerKeyStore.KeystoreDefaultName,
                KeystorePassword,
                NullLogger.Instance);
            var signingKey = await store.GetSigningCredentialsAsync();
            var validationKeys = (await store.GetValidationKeysAsync()).ToList();
            Assert.IsNotNull(signingKey);
            Assert.IsNotNull(validationKeys);
            Assert.AreEqual(2, validationKeys.Count);
            Assert.AreEqual(signingKey.Key, validationKeys.First().Key);
        }

        [Test]
        public void CertFileNotFound()
        {
            var store = new CertManagerKeyStore(
                "incorrect",
                CertManagerKeyStore.KeyDefaultName,
                CertManagerKeyStore.KeystoreDefaultName,
                KeystorePassword,
                NullLogger.Instance);
            Assert.CatchAsync<FileNotFoundException>(() => store.GetSigningCredentialsAsync());
        }

        [Test]
        public void KeyFileNotFound()
        {
            var store = new CertManagerKeyStore(
                CertManagerKeyStore.CrtDefaultName,
                "incorrect",
                CertManagerKeyStore.KeystoreDefaultName,
                KeystorePassword,
                NullLogger.Instance);
            Assert.CatchAsync<FileNotFoundException>(() => store.GetSigningCredentialsAsync());
        }
    }
}