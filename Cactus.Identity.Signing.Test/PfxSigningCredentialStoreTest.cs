using System.IO;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging.Abstractions;
using NUnit.Framework;

namespace Cactus.Identity.Signing.Test
{
    public class PfxSigningCredentialStoreTest
    {
        [Test]
        public async Task LoadFromFilesSuccess()
        {
            var store = new PfxSigningCredentialStore("cert.pfx", NullLogger.Instance);
            var res = await store.GetSigningCredentialsAsync();
            Assert.IsNotNull(res);
        }
        
        [Test]
        public void CertFileNotFound()
        {
            var store = new PfxSigningCredentialStore("incorrect.pfx", NullLogger.Instance);
            Assert.CatchAsync<FileNotFoundException>(()=>store.GetSigningCredentialsAsync());
        }
    }
}