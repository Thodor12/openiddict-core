using Microsoft.IdentityModel.Tokens;
using System.Diagnostics.CodeAnalysis;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace OpenIddict.Server
{
    internal class OpenIddictServerInMemorySigningCredentialsResolver : IOpenIddictServerSigningCredentialsResolver
    {
        private readonly ICollection<SigningCredentials> _signingCredentials;

        internal OpenIddictServerInMemorySigningCredentialsResolver()
            : this(new List<SigningCredentials>())
        {
        }

        internal OpenIddictServerInMemorySigningCredentialsResolver(ICollection<SigningCredentials> signingCredentials)
        {
            _signingCredentials = signingCredentials;
        }

        public SigningCredentials GetCurrentSigningCredential()
        {
            return _signingCredentials.First();
        }

        public ICollection<SigningCredentials> GetSigningCredentials()
        {
            return _signingCredentials;
        }
    }

    public class OpenIddictServerInMemorySigningCredentialsResolverBuilder
    {
        private readonly ICollection<SigningCredentials> _signingCredentials = new List<SigningCredentials>();

        #region Signing credential generator methods

        /// <summary>
        /// Registers signing credentials.
        /// </summary>
        /// <param name="credentials">The signing credentials.</param>
        /// <returns>The <see cref="OpenIddictServerInMemorySigningCredentialsResolverBuilder"/>.</returns>
        public OpenIddictServerInMemorySigningCredentialsResolverBuilder AddSigningCredentials(SigningCredentials credentials)
        {
            if (credentials is null)
            {
                throw new ArgumentNullException(nameof(credentials));
            }

            _signingCredentials.Add(credentials);
            return this;
        }

        /// <summary>
        /// Registers a signing key.
        /// </summary>
        /// <param name="key">The security key.</param>
        /// <returns>The <see cref="OpenIddictServerInMemorySigningCredentialsResolverBuilder"/>.</returns>
        public OpenIddictServerInMemorySigningCredentialsResolverBuilder AddSigningKey(SecurityKey key)
        {
            if (key is null)
            {
                throw new ArgumentNullException(nameof(key));
            }

            // If the signing key is an asymmetric security key, ensure it has a private key.
            if (key is AsymmetricSecurityKey asymmetricSecurityKey &&
                asymmetricSecurityKey.PrivateKeyStatus == PrivateKeyStatus.DoesNotExist)
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0067));
            }

            if (key.IsSupportedAlgorithm(SecurityAlgorithms.RsaSha256))
            {
                return AddSigningCredentials(new SigningCredentials(key, SecurityAlgorithms.RsaSha256));
            }

            if (key.IsSupportedAlgorithm(SecurityAlgorithms.HmacSha256))
            {
                return AddSigningCredentials(new SigningCredentials(key, SecurityAlgorithms.HmacSha256));
            }

#if SUPPORTS_ECDSA
                // Note: ECDSA algorithms are bound to specific curves and must be treated separately.
                if (key.IsSupportedAlgorithm(SecurityAlgorithms.EcdsaSha256))
                {
                    return AddSigningCredentials(new SigningCredentials(key, SecurityAlgorithms.EcdsaSha256));
                }

                if (key.IsSupportedAlgorithm(SecurityAlgorithms.EcdsaSha384))
                {
                    return AddSigningCredentials(new SigningCredentials(key, SecurityAlgorithms.EcdsaSha384));
                }

                if (key.IsSupportedAlgorithm(SecurityAlgorithms.EcdsaSha512))
                {
                    return AddSigningCredentials(new SigningCredentials(key, SecurityAlgorithms.EcdsaSha512));
                }
#else
            if (key.IsSupportedAlgorithm(SecurityAlgorithms.EcdsaSha256) ||
                key.IsSupportedAlgorithm(SecurityAlgorithms.EcdsaSha384) ||
                key.IsSupportedAlgorithm(SecurityAlgorithms.EcdsaSha512))
            {
                throw new PlatformNotSupportedException(SR.GetResourceString(SR.ID0069));
            }
#endif

            throw new InvalidOperationException(SR.GetResourceString(SR.ID0068));
        }

        /// <summary>
        /// Registers (and generates if necessary) a user-specific development signing certificate.
        /// </summary>
        /// <returns>The <see cref="OpenIddictServerInMemorySigningCredentialsResolverBuilder"/>.</returns>
        public OpenIddictServerInMemorySigningCredentialsResolverBuilder AddDevelopmentSigningCertificate()
            => AddDevelopmentSigningCertificate(new X500DistinguishedName("CN=OpenIddict Server Signing Certificate"));

        /// <summary>
        /// Registers (and generates if necessary) a user-specific development signing certificate.
        /// </summary>
        /// <param name="subject">The subject name associated with the certificate.</param>
        /// <returns>The <see cref="OpenIddictServerInMemorySigningCredentialsResolverBuilder"/>.</returns>
        [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
            Justification = "The X.509 certificate is attached to the server options.")]
        public OpenIddictServerInMemorySigningCredentialsResolverBuilder AddDevelopmentSigningCertificate(X500DistinguishedName subject)
        {
            if (subject is null)
            {
                throw new ArgumentNullException(nameof(subject));
            }

            using var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadWrite);

            // Try to retrieve the existing development certificates from the specified store.
            // If no valid existing certificate was found, create a new signing certificate.
            var certificates = store.Certificates.Find(X509FindType.FindBySubjectDistinguishedName, subject.Name, validOnly: false)
                .OfType<X509Certificate2>()
                .ToList();

            if (!certificates.Any(certificate => certificate.NotBefore < DateTime.Now && certificate.NotAfter > DateTime.Now))
            {
#if SUPPORTS_CERTIFICATE_GENERATION
                    using var algorithm = RSA.Create(keySizeInBits: 2048);

                    var request = new CertificateRequest(subject, algorithm, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                    request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, critical: true));

                    var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddYears(2));

                    // Note: setting the friendly name is not supported on Unix machines (including Linux and macOS).
                    // To ensure an exception is not thrown by the property setter, an OS runtime check is used here.
                    if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                    {
                        certificate.FriendlyName = "OpenIddict Server Development Signing Certificate";
                    }

                    // Note: CertificateRequest.CreateSelfSigned() doesn't mark the key set associated with the certificate
                    // as "persisted", which eventually prevents X509Store.Add() from correctly storing the private key.
                    // To work around this issue, the certificate payload is manually exported and imported back
                    // into a new X509Certificate2 instance specifying the X509KeyStorageFlags.PersistKeySet flag.
                    var data = certificate.Export(X509ContentType.Pfx, string.Empty);

                    try
                    {
                        var flags = X509KeyStorageFlags.PersistKeySet;

                        // Note: macOS requires marking the certificate private key as exportable.
                        // If this flag is not set, a CryptographicException is thrown at runtime.
                        if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
                        {
                            flags |= X509KeyStorageFlags.Exportable;
                        }

                        certificates.Insert(0, certificate = new X509Certificate2(data, string.Empty, flags));
                    }

                    finally
                    {
                        Array.Clear(data, 0, data.Length);
                    }

                    store.Add(certificate);
#else
                throw new PlatformNotSupportedException(SR.GetResourceString(SR.ID0264));
#endif
            }

            IEnumerable<SigningCredentials> credentials = certificates
                .Select(certificate => new X509SecurityKey(certificate))
                .Select(key => new SigningCredentials(key, SecurityAlgorithms.RsaSha256));
            foreach (var credential in credentials)
            {
                _signingCredentials.Add(credential);
            }
            return this;
        }

        /// <summary>
        /// Registers a new ephemeral signing key. Ephemeral signing keys are automatically
        /// discarded when the application shuts down and payloads signed using this key are
        /// automatically invalidated. This method should only be used during development.
        /// On production, using a X.509 certificate stored in the machine store is recommended.
        /// </summary>
        /// <returns>The <see cref="OpenIddictServerInMemorySigningCredentialsResolverBuilder"/>.</returns>
        public OpenIddictServerInMemorySigningCredentialsResolverBuilder AddEphemeralSigningKey()
            => AddEphemeralSigningKey(SecurityAlgorithms.RsaSha256);

        /// <summary>
        /// Registers a new ephemeral signing key. Ephemeral signing keys are automatically
        /// discarded when the application shuts down and payloads signed using this key are
        /// automatically invalidated. This method should only be used during development.
        /// On production, using a X.509 certificate stored in the machine store is recommended.
        /// </summary>
        /// <param name="algorithm">The algorithm associated with the signing key.</param>
        /// <returns>The <see cref="OpenIddictServerInMemorySigningCredentialsResolverBuilder"/>.</returns>
        [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
            Justification = "The X.509 certificate is attached to the server options.")]
        public OpenIddictServerInMemorySigningCredentialsResolverBuilder AddEphemeralSigningKey(string algorithm)
        {
            if (string.IsNullOrEmpty(algorithm))
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID0057), nameof(algorithm));
            }

            return algorithm switch
            {
                SecurityAlgorithms.RsaSha256 or
                SecurityAlgorithms.RsaSha384 or
                SecurityAlgorithms.RsaSha512 or
                SecurityAlgorithms.RsaSha256Signature or
                SecurityAlgorithms.RsaSha384Signature or
                SecurityAlgorithms.RsaSha512Signature or
                SecurityAlgorithms.RsaSsaPssSha256 or
                SecurityAlgorithms.RsaSsaPssSha384 or
                SecurityAlgorithms.RsaSsaPssSha512 or
                SecurityAlgorithms.RsaSsaPssSha256Signature or
                SecurityAlgorithms.RsaSsaPssSha384Signature or
                SecurityAlgorithms.RsaSsaPssSha512Signature
                    => AddSigningCredentials(new SigningCredentials(CreateRsaSecurityKey(2048), algorithm)),

#if SUPPORTS_ECDSA
                    SecurityAlgorithms.EcdsaSha256 or
                    SecurityAlgorithms.EcdsaSha256Signature
                        => AddSigningCredentials(new SigningCredentials(new ECDsaSecurityKey(
                            ECDsa.Create(ECCurve.NamedCurves.nistP256)), algorithm)),

                    SecurityAlgorithms.EcdsaSha384 or
                    SecurityAlgorithms.EcdsaSha384Signature
                        => AddSigningCredentials(new SigningCredentials(new ECDsaSecurityKey(
                            ECDsa.Create(ECCurve.NamedCurves.nistP384)), algorithm)),

                    SecurityAlgorithms.EcdsaSha512 or
                    SecurityAlgorithms.EcdsaSha512Signature
                        => AddSigningCredentials(new SigningCredentials(new ECDsaSecurityKey(
                            ECDsa.Create(ECCurve.NamedCurves.nistP521)), algorithm)),
#else
                SecurityAlgorithms.EcdsaSha256 or
                SecurityAlgorithms.EcdsaSha384 or
                SecurityAlgorithms.EcdsaSha512 or
                SecurityAlgorithms.EcdsaSha256Signature or
                SecurityAlgorithms.EcdsaSha384Signature or
                SecurityAlgorithms.EcdsaSha512Signature
                    => throw new PlatformNotSupportedException(SR.GetResourceString(SR.ID0069)),
#endif

                _ => throw new InvalidOperationException(SR.GetResourceString(SR.ID0058)),
            };

            [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
                Justification = "The generated RSA key is attached to the server options.")]
            static RsaSecurityKey CreateRsaSecurityKey(int size)
            {
#if SUPPORTS_DIRECT_KEY_CREATION_WITH_SPECIFIED_SIZE
                    return new RsaSecurityKey(RSA.Create(size));
#else
                // Note: a 1024-bit key might be returned by RSA.Create() on .NET Desktop/Mono,
                // where RSACryptoServiceProvider is still the default implementation and
                // where custom implementations can be registered via CryptoConfig.
                // To ensure the key size is always acceptable, replace it if necessary.
                var algorithm = RSA.Create();
                if (algorithm.KeySize < size)
                {
                    algorithm.KeySize = size;
                }

                if (algorithm.KeySize < size && algorithm is RSACryptoServiceProvider)
                {
                    algorithm.Dispose();
                    algorithm = new RSACryptoServiceProvider(size);
                }

                if (algorithm.KeySize < size)
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0059));
                }

                return new RsaSecurityKey(algorithm);
#endif
            }
        }

        /// <summary>
        /// Registers a signing certificate.
        /// </summary>
        /// <param name="certificate">The signing certificate.</param>
        /// <returns>The <see cref="OpenIddictServerInMemorySigningCredentialsResolverBuilder"/>.</returns>
        public OpenIddictServerInMemorySigningCredentialsResolverBuilder AddSigningCertificate(X509Certificate2 certificate)
        {
            if (certificate is null)
            {
                throw new ArgumentNullException(nameof(certificate));
            }

            // If the certificate is a X.509v3 certificate that specifies at least
            // one key usage, ensure that the certificate key can be used for signing.
            if (certificate.Version >= 3)
            {
                var extensions = certificate.Extensions.OfType<X509KeyUsageExtension>().ToList();
                if (extensions.Count != 0 && !extensions.Any(extension => extension.KeyUsages.HasFlag(X509KeyUsageFlags.DigitalSignature)))
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0070));
                }
            }

            if (!certificate.HasPrivateKey)
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0061));
            }

            return AddSigningKey(new X509SecurityKey(certificate));
        }

        /// <summary>
        /// Registers a signing certificate retrieved from an embedded resource.
        /// </summary>
        /// <param name="assembly">The assembly containing the certificate.</param>
        /// <param name="resource">The name of the embedded resource.</param>
        /// <param name="password">The password used to open the certificate.</param>
        /// <returns>The <see cref="OpenIddictServerInMemorySigningCredentialsResolverBuilder"/>.</returns>
        public OpenIddictServerInMemorySigningCredentialsResolverBuilder AddSigningCertificate(Assembly assembly, string resource, string? password)
#if SUPPORTS_EPHEMERAL_KEY_SETS
                // Note: ephemeral key sets are currently not supported on macOS.
                => AddSigningCertificate(assembly, resource, password, RuntimeInformation.IsOSPlatform(OSPlatform.OSX) ?
                    X509KeyStorageFlags.MachineKeySet :
                    X509KeyStorageFlags.EphemeralKeySet);
#else
                => AddSigningCertificate(assembly, resource, password, X509KeyStorageFlags.MachineKeySet);
#endif

        /// <summary>
        /// Registers a signing certificate retrieved from an embedded resource.
        /// </summary>
        /// <param name="assembly">The assembly containing the certificate.</param>
        /// <param name="resource">The name of the embedded resource.</param>
        /// <param name="password">The password used to open the certificate.</param>
        /// <param name="flags">An enumeration of flags indicating how and where to store the private key of the certificate.</param>
        /// <returns>The <see cref="OpenIddictServerInMemorySigningCredentialsResolverBuilder"/>.</returns>
        public OpenIddictServerInMemorySigningCredentialsResolverBuilder AddSigningCertificate(
            Assembly assembly, string resource,
            string? password, X509KeyStorageFlags flags)
        {
            if (assembly is null)
            {
                throw new ArgumentNullException(nameof(assembly));
            }

            if (string.IsNullOrEmpty(resource))
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID0062), nameof(resource));
            }

            using var stream = assembly.GetManifestResourceStream(resource);
            if (stream is null)
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0064));
            }

            return AddSigningCertificate(stream, password, flags);
        }

        /// <summary>
        /// Registers a signing certificate extracted from a stream.
        /// </summary>
        /// <param name="stream">The stream containing the certificate.</param>
        /// <param name="password">The password used to open the certificate.</param>
        /// <returns>The <see cref="OpenIddictServerInMemorySigningCredentialsResolverBuilder"/>.</returns>
        public OpenIddictServerInMemorySigningCredentialsResolverBuilder AddSigningCertificate(Stream stream, string? password)
#if SUPPORTS_EPHEMERAL_KEY_SETS
                // Note: ephemeral key sets are currently not supported on macOS.
                => AddSigningCertificate(stream, password, RuntimeInformation.IsOSPlatform(OSPlatform.OSX) ?
                    X509KeyStorageFlags.MachineKeySet :
                    X509KeyStorageFlags.EphemeralKeySet);
#else
                => AddSigningCertificate(stream, password, X509KeyStorageFlags.MachineKeySet);
#endif

        /// <summary>
        /// Registers a signing certificate extracted from a stream.
        /// </summary>
        /// <param name="stream">The stream containing the certificate.</param>
        /// <param name="password">The password used to open the certificate.</param>
        /// <param name="flags">
        /// An enumeration of flags indicating how and where
        /// to store the private key of the certificate.
        /// </param>
        /// <returns>The <see cref="OpenIddictServerInMemorySigningCredentialsResolverBuilder"/>.</returns>
        [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
            Justification = "The X.509 certificate is attached to the server options.")]
        public OpenIddictServerInMemorySigningCredentialsResolverBuilder AddSigningCertificate(Stream stream, string? password, X509KeyStorageFlags flags)
        {
            if (stream is null)
            {
                throw new ArgumentNullException(nameof(stream));
            }

            using var buffer = new MemoryStream();
            stream.CopyTo(buffer);

            return AddSigningCertificate(new X509Certificate2(buffer.ToArray(), password, flags));
        }

        /// <summary>
        /// Registers a signing certificate retrieved from the X.509 user or machine store.
        /// </summary>
        /// <param name="thumbprint">The thumbprint of the certificate used to identify it in the X.509 store.</param>
        /// <returns>The <see cref="OpenIddictServerInMemorySigningCredentialsResolverBuilder"/>.</returns>
        public OpenIddictServerInMemorySigningCredentialsResolverBuilder AddSigningCertificate(string thumbprint)
        {
            if (string.IsNullOrEmpty(thumbprint))
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID0065), nameof(thumbprint));
            }

            var certificate = GetCertificate(StoreLocation.CurrentUser, thumbprint) ?? GetCertificate(StoreLocation.LocalMachine, thumbprint);
            if (certificate is null)
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0066));
            }

            return AddSigningCertificate(certificate);

            static X509Certificate2? GetCertificate(StoreLocation location, string thumbprint)
            {
                using var store = new X509Store(StoreName.My, location);
                store.Open(OpenFlags.ReadOnly);

                return store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, validOnly: false)
                    .OfType<X509Certificate2>()
                    .SingleOrDefault();
            }
        }

        /// <summary>
        /// Registers a signing certificate retrieved from the specified X.509 store.
        /// </summary>
        /// <param name="thumbprint">The thumbprint of the certificate used to identify it in the X.509 store.</param>
        /// <param name="name">The name of the X.509 store.</param>
        /// <param name="location">The location of the X.509 store.</param>
        /// <returns>The <see cref="OpenIddictServerInMemorySigningCredentialsResolverBuilder"/>.</returns>
        public OpenIddictServerInMemorySigningCredentialsResolverBuilder AddSigningCertificate(string thumbprint, StoreName name, StoreLocation location)
        {
            if (string.IsNullOrEmpty(thumbprint))
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID0065), nameof(thumbprint));
            }

            using var store = new X509Store(name, location);
            store.Open(OpenFlags.ReadOnly);

            var certificate = store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, validOnly: false)
                .OfType<X509Certificate2>()
                .SingleOrDefault();

            if (certificate is null)
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0066));
            }

            return AddSigningCertificate(certificate);
        }

        #endregion

        /// <summary>
        /// Constructs the InMemory signing credentials resolver
        /// </summary>
        /// <returns></returns>
        internal OpenIddictServerInMemorySigningCredentialsResolver Build()
        {
            return new OpenIddictServerInMemorySigningCredentialsResolver(_signingCredentials);
        }
    }
}
