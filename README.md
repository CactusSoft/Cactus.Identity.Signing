# Cactus.Identity.Signing
[ ![Download](https://travis-ci.com/CactusSoft/Cactus.Identity.Signing.svg?branch=develop) ](https://travis-ci.com/CactusSoft/Cactus.Identity.Signing)
[ ![Download](https://codecov.io/gh/CactusSoft/Cactus.Identity.Signing/graph/badge.svg) ](https://codecov.io/gh/CactusSoft/Cactus.Identity.Signing)

Library to implement [IdentityServer4](https://github.com/IdentityServer/IdentityServer4) signing key rollover issued by [CertManager](https://cert-manager.io/docs/) in k8s infrastructure.
The workflow is the following:
- CertManager generates Secret that contains current signing key (`tls.crt`, `tls.key`) and PKCS12 keystore that contains CA & previously issued certificate (`keystore.p12`).
- Identity service mount the Secret to filesystem. So it gets files `tls.crt`, `tls.key` and `keystore.p12`
- To load signing key the service uses `PemSigningCredentialStore` class which implements `ISigningCredentialStore`   
- To load previously issued certificates, the service uses `Pkcs12ValidationKeysStore` class that implements `IValidationKeysStore`
- Both implementations of `ISigningCredentialStore` and `IValidationKeysStore` are injected to IdentityServer4

To get more details about IdentityServer4 keys rollover see the [official documentation](https://docs.identityserver.io/en/latest/topics/crypto.html).
