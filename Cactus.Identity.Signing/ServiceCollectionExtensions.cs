using System;
using System.IO;
using IdentityServer4.Stores;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Cactus.Identity.Signing
{
    public static class ServiceCollectionExtensions
    {
        public static IServiceCollection AddCertManagerSigningCredential(
            this IServiceCollection services,
            string folder,
            string keystorePassword)
        {
            _ = folder ?? throw new ArgumentNullException(nameof(folder));
            _ = keystorePassword ?? throw new ArgumentNullException(nameof(keystorePassword));

            if (!Directory.Exists(folder))
            {
                throw new FileNotFoundException($"Folder {folder} not found");
            }

            services.AddSingleton(c =>
                new CertManagerKeyStore(folder, keystorePassword,
                    c.GetRequiredService<ILogger<CertManagerKeyStore>>()));
            services.AddSingleton<ISigningCredentialStore>(c => c.GetRequiredService<CertManagerKeyStore>());
            services.AddSingleton<IValidationKeysStore>(c => c.GetRequiredService<CertManagerKeyStore>());
            return services;
        }

        public static IServiceCollection AddSinglePfxSigningCredential(this IServiceCollection services, string pfxFile)
        {
            _ = pfxFile ?? throw new ArgumentNullException(nameof(pfxFile));

            if (!File.Exists(pfxFile))
            {
                throw new FileNotFoundException($"File {pfxFile} not found");
            }

            services.AddSingleton(c =>
                new SinglePfxKeyStore(pfxFile, c.GetRequiredService<ILogger<SinglePfxKeyStore>>()));
            services.AddSingleton<ISigningCredentialStore>(c => c.GetRequiredService<SinglePfxKeyStore>());
            services.AddSingleton<IValidationKeysStore>(c => c.GetRequiredService<SinglePfxKeyStore>());
            return services;
        }
    }
}