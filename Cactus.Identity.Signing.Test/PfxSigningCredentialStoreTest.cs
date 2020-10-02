using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging.Abstractions;
using NUnit.Framework;

namespace Cactus.Identity.Signing.Test
{
    public class SinglePfxStoreTest
    {
        [Test]
        public async Task LoadFromFilesSuccess()
        {
            var store = new SinglePfxKeyStore("cert.pfx", NullLogger.Instance);
            var signingKey = await store.GetSigningCredentialsAsync();
            var validationKeys = (await store.GetValidationKeysAsync()).ToList();

            Assert.IsNotNull(signingKey);
            Assert.IsNotNull(validationKeys);
            Assert.AreEqual(1, validationKeys.Count);
            Assert.AreEqual(signingKey.Key, validationKeys.First().Key);
        }

        [Test]
        public void CertFileNotFound()
        {
            var store = new SinglePfxKeyStore("incorrect.pfx", NullLogger.Instance);
            Assert.CatchAsync<FileNotFoundException>(() => store.GetSigningCredentialsAsync());
        }
    }
}