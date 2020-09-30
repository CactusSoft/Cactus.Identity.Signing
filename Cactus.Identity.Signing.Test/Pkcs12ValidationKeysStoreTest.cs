using System.Linq;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging.Abstractions;
using NUnit.Framework;

namespace Cactus.Identity.Signing.Test
{
    public class Pkcs12ValidationKeyStoresTest
    {
        [Test]
        public async Task LoadKeystoreSuccess()
        {
            var keystore = new Pkcs12ValidationKeysStore(Pkcs12ValidationKeysStore.KeystoreDefaultName, "supersecret", NullLogger.Instance);
            var res = (await keystore.GetValidationKeysAsync()).ToList();
            Assert.IsNotNull(res);
            Assert.AreEqual(1, res.Count);
        }
        
        [Test]
        public async Task LoadKeystoreIncorrectPassword()
        {
            var keystore = new Pkcs12ValidationKeysStore(Pkcs12ValidationKeysStore.KeystoreDefaultName, "incorrect", NullLogger.Instance);
            var res = (await keystore.GetValidationKeysAsync()).ToList();
            Assert.IsNotNull(res);
            Assert.AreEqual(0, res.Count);
        }
        
        [Test]
        public async Task LoadKeystoreIncorrectFile()
        {
            var keystore = new Pkcs12ValidationKeysStore("incorrect", "supersecret", NullLogger.Instance);
            var res = (await keystore.GetValidationKeysAsync()).ToList();
            Assert.IsNotNull(res);
            Assert.AreEqual(0, res.Count);
        }
    }
}