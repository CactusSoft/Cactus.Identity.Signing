using System.Linq;
using NUnit.Framework;

namespace Cactus.Identity.Signing.Test
{
    public class Pkcs12KeystoreTest
    {
        [Test]
        public void LoadKeystore()
        {
            var keystore = Pkcs12Keystore.Load("keystore.p12", "supersecret");
            Assert.IsNotNull(keystore);
            Assert.AreEqual(2, keystore.Certificates.Count());
            Assert.AreEqual(1, keystore.Certificates.Count(e => e.Issuer == e.Subject));
        }
    }
}