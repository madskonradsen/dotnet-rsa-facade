# C# RSACryptoService

Asymmetric encryption is only designed for encrypting data smaller than it's key size. So always use assymetric to exchange a symmetric key.
Using PKCS#1 v1.5 padding

## Basic usage

```csharp
using RSACryptoService;

RSACrypto rsaCrypto = new RSACrypto();
```