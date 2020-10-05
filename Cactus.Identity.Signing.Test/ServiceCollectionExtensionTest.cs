using System;
using System.IO;
using IdentityServer4.Stores;
using Microsoft.Extensions.DependencyInjection;
using NUnit.Framework;

namespace Cactus.Identity.Signing.Test
{
    [TestFixture]
    public class ServiceCollectionExtensionTest
    {
        [Test]
        public void AddCertManagerSigningCredentialTest()
        {
            var di = new ServiceCollection();
            di.AddLogging();
            Assert.Catch<ArgumentNullException>(()=>di.AddCertManagerSigningCredential(null, "pass"));
            Assert.Catch<ArgumentNullException>(()=>di.AddCertManagerSigningCredential(".", null));
            Assert.Catch<FileNotFoundException>(()=>di.AddCertManagerSigningCredential("non-existing-folder", "pass"));
            
            di.AddCertManagerSigningCredential(".", "pass");
            var sp = di.BuildServiceProvider();
            sp.GetRequiredService<ISigningCredentialStore>();
            sp.GetRequiredService<IValidationKeysStore>();
        }
        
        [Test]
        public void AddSinglePfxSigningCredentialTest()
        {
            var di = new ServiceCollection();
            di.AddLogging();
            Assert.Catch<ArgumentNullException>(()=>di.AddSinglePfxSigningCredential(null));
            Assert.Catch<FileNotFoundException>(()=>di.AddSinglePfxSigningCredential("non-existing-file"));
            
            di.AddSinglePfxSigningCredential("cert.pfx");
            var sp = di.BuildServiceProvider();
            sp.GetRequiredService<ISigningCredentialStore>();
            sp.GetRequiredService<IValidationKeysStore>();
        }
    }
}