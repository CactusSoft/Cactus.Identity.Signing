using System.IO;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging.Abstractions;
using NUnit.Framework;

namespace Cactus.Identity.Signing.Test
{
    public class PemSigningCredentialStoreTest
    {
        [Test]
        public async Task LoadFromFolderSuccess()
        {
            var store = new PemSigningCredentialStore(".", NullLogger.Instance);
            var res = await store.GetSigningCredentialsAsync();
            Assert.IsNotNull(res);
        }
        
        [Test]
        public async Task LoadFromFilesSuccess()
        {
            var store = new PemSigningCredentialStore(
                PemSigningCredentialStore.CrtDefaultName,
                PemSigningCredentialStore.KeyDefaultName,
                NullLogger.Instance);
            var res = await store.GetSigningCredentialsAsync();
            Assert.IsNotNull(res);
        }
        
        [Test]
        public void CertFileNotFound()
        {
            var store = new PemSigningCredentialStore(
                "incorrect.crt",
                PemSigningCredentialStore.KeyDefaultName,
                NullLogger.Instance);
            Assert.CatchAsync<FileNotFoundException>(()=>store.GetSigningCredentialsAsync());
        }
        
        [Test]
        public void KeyFileNotFound()
        {
            var store = new PemSigningCredentialStore(
                PemSigningCredentialStore.CrtDefaultName,
                "incorrect.key",
                NullLogger.Instance);
            Assert.CatchAsync<FileNotFoundException>(()=>store.GetSigningCredentialsAsync());
        }
    }
}