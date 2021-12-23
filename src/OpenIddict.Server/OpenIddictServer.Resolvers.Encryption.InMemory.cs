using Microsoft.IdentityModel.Tokens;
using System.Diagnostics.CodeAnalysis;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace OpenIddict.Server
{
    internal class OpenIddictServerInMemoryEncryptionCredentialsResolver : IOpenIddictServerEncryptionCredentialsResolver
    {
        private readonly ICollection<EncryptingCredentials> _encryptionCredentials;

        internal OpenIddictServerInMemoryEncryptionCredentialsResolver()
            : this(new List<EncryptingCredentials>())
        {
        }

        internal OpenIddictServerInMemoryEncryptionCredentialsResolver(ICollection<EncryptingCredentials> encryptionCredentials)
        {
            _encryptionCredentials = encryptionCredentials;
        }

        public EncryptingCredentials GetCurrentEncryptionCredential()
        {
            return _encryptionCredentials.First();
        }

        public ICollection<EncryptingCredentials> GetEncryptionCredentials()
        {
            return _encryptionCredentials;
        }
    }

    public class OpenIddictServerInMemoryEncryptionCredentialsResolverBuilder
    {
        private readonly ICollection<EncryptingCredentials> _encryptionCredentials = new List<EncryptingCredentials>();

        #region Encryption credential generator methods

        /// <summary>
        /// Registers encryption credentials.
        /// </summary>
        /// <param name="credentials">The encrypting credentials.</param>
        /// <returns>The <see cref="OpenIddictServerInMemoryEncryptionCredentialsResolverBuilder"/>.</returns>
        public OpenIddictServerInMemoryEncryptionCredentialsResolverBuilder AddEncryptionCredentials(EncryptingCredentials credentials)
        {
            if (credentials is null)
            {
                throw new ArgumentNullException(nameof(credentials));
            }

            _encryptionCredentials.Add(credentials);
            return this;
        }

        /// <summary>
        /// Registers an encryption key.
        /// </summary>
        /// <param name="key">The security key.</param>
        /// <returns>The <see cref="OpenIddictServerInMemoryEncryptionCredentialsResolverBuilder"/>.</returns>
        public OpenIddictServerInMemoryEncryptionCredentialsResolverBuilder AddEncryptionKey(SecurityKey key)
        {
            if (key is null)
            {
                throw new ArgumentNullException(nameof(key));
            }

            // If the encryption key is an asymmetric security key, ensure it has a private key.
            if (key is AsymmetricSecurityKey asymmetricSecurityKey &&
                asymmetricSecurityKey.PrivateKeyStatus == PrivateKeyStatus.DoesNotExist)
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0055));
            }

            if (key.IsSupportedAlgorithm(SecurityAlgorithms.Aes256KW))
            {
                if (key.KeySize != 256)
                {
                    throw new InvalidOperationException(SR.FormatID0283(256, key.KeySize));
                }

                return AddEncryptionCredentials(new EncryptingCredentials(key,
                    SecurityAlgorithms.Aes256KW, SecurityAlgorithms.Aes256CbcHmacSha512));
            }

            if (key.IsSupportedAlgorithm(SecurityAlgorithms.RsaOAEP))
            {
                return AddEncryptionCredentials(new EncryptingCredentials(key,
                    SecurityAlgorithms.RsaOAEP, SecurityAlgorithms.Aes256CbcHmacSha512));
            }

            throw new InvalidOperationException(SR.GetResourceString(SR.ID0056));
        }

        /// <summary>
        /// Registers (and generates if necessary) a user-specific development encryption certificate.
        /// </summary>
        /// <returns>The <see cref="OpenIddictServerInMemoryEncryptionCredentialsResolverBuilder"/>.</returns>
        public OpenIddictServerInMemoryEncryptionCredentialsResolverBuilder AddDevelopmentEncryptionCertificate()
            => AddDevelopmentEncryptionCertificate(new X500DistinguishedName("CN=OpenIddict Server Encryption Certificate"));

        /// <summary>
        /// Registers (and generates if necessary) a user-specific development encryption certificate.
        /// </summary>
        /// <param name="subject">The subject name associated with the certificate.</param>
        /// <returns>The <see cref="OpenIddictServerInMemoryEncryptionCredentialsResolverBuilder"/>.</returns>
        [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
            Justification = "The X.509 certificate is attached to the server options.")]
        public OpenIddictServerInMemoryEncryptionCredentialsResolverBuilder AddDevelopmentEncryptionCertificate(X500DistinguishedName subject)
        {
            if (subject is null)
            {
                throw new ArgumentNullException(nameof(subject));
            }

            using var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadWrite);

            // Try to retrieve the existing development certificates from the specified store.
            // If no valid existing certificate was found, create a new encryption certificate.
            var certificates = store.Certificates.Find(X509FindType.FindBySubjectDistinguishedName, subject.Name, validOnly: false)
                .OfType<X509Certificate2>()
                .ToList();

            if (!certificates.Any(certificate => certificate.NotBefore < DateTime.Now && certificate.NotAfter > DateTime.Now))
            {
#if SUPPORTS_CERTIFICATE_GENERATION
                    using var algorithm = RSA.Create(keySizeInBits: 2048);

                    var request = new CertificateRequest(subject, algorithm, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                    request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyEncipherment, critical: true));

                    var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddYears(2));

                    // Note: setting the friendly name is not supported on Unix machines (including Linux and macOS).
                    // To ensure an exception is not thrown by the property setter, an OS runtime check is used here.
                    if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                    {
                        certificate.FriendlyName = "OpenIddict Server Development Encryption Certificate";
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

            IEnumerable<EncryptingCredentials> credentials = certificates
                .Select(certificate => new X509SecurityKey(certificate))
                .Select(key => new EncryptingCredentials(key, SecurityAlgorithms.RsaOAEP, SecurityAlgorithms.Aes256CbcHmacSha512));
            foreach (var credential in credentials)
            {
                _encryptionCredentials.Add(credential);
            }
            return this;
        }

        /// <summary>
        /// Registers a new ephemeral encryption key. Ephemeral encryption keys are automatically
        /// discarded when the application shuts down and payloads encrypted using this key are
        /// automatically invalidated. This method should only be used during development.
        /// On production, using a X.509 certificate stored in the machine store is recommended.
        /// </summary>
        /// <returns>The <see cref="OpenIddictServerInMemoryEncryptionCredentialsResolverBuilder"/>.</returns>
        public OpenIddictServerInMemoryEncryptionCredentialsResolverBuilder AddEphemeralEncryptionKey()
            => AddEphemeralEncryptionKey(SecurityAlgorithms.RsaOAEP);

        /// <summary>
        /// Registers a new ephemeral encryption key. Ephemeral encryption keys are automatically
        /// discarded when the application shuts down and payloads encrypted using this key are
        /// automatically invalidated. This method should only be used during development.
        /// On production, using a X.509 certificate stored in the machine store is recommended.
        /// </summary>
        /// <param name="algorithm">The algorithm associated with the encryption key.</param>
        /// <returns>The <see cref="OpenIddictServerInMemoryEncryptionCredentialsResolverBuilder"/>.</returns>
        public OpenIddictServerInMemoryEncryptionCredentialsResolverBuilder AddEphemeralEncryptionKey(string algorithm)
        {
            if (string.IsNullOrEmpty(algorithm))
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID0057), nameof(algorithm));
            }

            return algorithm switch
            {
                SecurityAlgorithms.Aes256KW
                    => AddEncryptionCredentials(new EncryptingCredentials(CreateSymmetricSecurityKey(256),
                        algorithm, SecurityAlgorithms.Aes256CbcHmacSha512)),

                SecurityAlgorithms.RsaOAEP or
                SecurityAlgorithms.RsaOaepKeyWrap
                    => AddEncryptionCredentials(new EncryptingCredentials(CreateRsaSecurityKey(2048),
                        algorithm, SecurityAlgorithms.Aes256CbcHmacSha512)),

                _ => throw new InvalidOperationException(SR.GetResourceString(SR.ID0058)),
            };

            static SymmetricSecurityKey CreateSymmetricSecurityKey(int size)
            {
                var data = new byte[size / 8];

#if SUPPORTS_STATIC_RANDOM_NUMBER_GENERATOR_METHODS
                    RandomNumberGenerator.Fill(data);
#else
                using var generator = RandomNumberGenerator.Create();
                generator.GetBytes(data);
#endif

                return new SymmetricSecurityKey(data);
            }

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
        /// Registers an encryption certificate.
        /// </summary>
        /// <param name="certificate">The encryption certificate.</param>
        /// <returns>The <see cref="OpenIddictServerInMemoryEncryptionCredentialsResolverBuilder"/>.</returns>
        public OpenIddictServerInMemoryEncryptionCredentialsResolverBuilder AddEncryptionCertificate(X509Certificate2 certificate)
        {
            if (certificate is null)
            {
                throw new ArgumentNullException(nameof(certificate));
            }

            // If the certificate is a X.509v3 certificate that specifies at least one
            // key usage, ensure that the certificate key can be used for key encryption.
            if (certificate.Version >= 3)
            {
                var extensions = certificate.Extensions.OfType<X509KeyUsageExtension>().ToList();
                if (extensions.Count != 0 && !extensions.Any(extension => extension.KeyUsages.HasFlag(X509KeyUsageFlags.KeyEncipherment)))
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0060));
                }
            }

            if (!certificate.HasPrivateKey)
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0061));
            }

            return AddEncryptionKey(new X509SecurityKey(certificate));
        }

        /// <summary>
        /// Registers an encryption certificate retrieved from an embedded resource.
        /// </summary>
        /// <param name="assembly">The assembly containing the certificate.</param>
        /// <param name="resource">The name of the embedded resource.</param>
        /// <param name="password">The password used to open the certificate.</param>
        /// <returns>The <see cref="OpenIddictServerInMemoryEncryptionCredentialsResolverBuilder"/>.</returns>
        public OpenIddictServerInMemoryEncryptionCredentialsResolverBuilder AddEncryptionCertificate(Assembly assembly, string resource, string? password)
#if SUPPORTS_EPHEMERAL_KEY_SETS
                // Note: ephemeral key sets are currently not supported on macOS.
                => AddEncryptionCertificate(assembly, resource, password, RuntimeInformation.IsOSPlatform(OSPlatform.OSX) ?
                    X509KeyStorageFlags.MachineKeySet :
                    X509KeyStorageFlags.EphemeralKeySet);
#else
                => AddEncryptionCertificate(assembly, resource, password, X509KeyStorageFlags.MachineKeySet);
#endif

        /// <summary>
        /// Registers an encryption certificate retrieved from an embedded resource.
        /// </summary>
        /// <param name="assembly">The assembly containing the certificate.</param>
        /// <param name="resource">The name of the embedded resource.</param>
        /// <param name="password">The password used to open the certificate.</param>
        /// <param name="flags">An enumeration of flags indicating how and where to store the private key of the certificate.</param>
        /// <returns>The <see cref="OpenIddictServerInMemoryEncryptionCredentialsResolverBuilder"/>.</returns>
        public OpenIddictServerInMemoryEncryptionCredentialsResolverBuilder AddEncryptionCertificate(
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

            return AddEncryptionCertificate(stream, password, flags);
        }

        /// <summary>
        /// Registers an encryption certificate extracted from a stream.
        /// </summary>
        /// <param name="stream">The stream containing the certificate.</param>
        /// <param name="password">The password used to open the certificate.</param>
        /// <returns>The <see cref="OpenIddictServerInMemoryEncryptionCredentialsResolverBuilder"/>.</returns>
        public OpenIddictServerInMemoryEncryptionCredentialsResolverBuilder AddEncryptionCertificate(Stream stream, string? password)
#if SUPPORTS_EPHEMERAL_KEY_SETS
                // Note: ephemeral key sets are currently not supported on macOS.
                => AddEncryptionCertificate(stream, password, RuntimeInformation.IsOSPlatform(OSPlatform.OSX) ?
                    X509KeyStorageFlags.MachineKeySet :
                    X509KeyStorageFlags.EphemeralKeySet);
#else
                => AddEncryptionCertificate(stream, password, X509KeyStorageFlags.MachineKeySet);
#endif

        /// <summary>
        /// Registers an encryption certificate extracted from a stream.
        /// </summary>
        /// <param name="stream">The stream containing the certificate.</param>
        /// <param name="password">The password used to open the certificate.</param>
        /// <param name="flags">
        /// An enumeration of flags indicating how and where
        /// to store the private key of the certificate.
        /// </param>
        /// <returns>The <see cref="OpenIddictServerInMemoryEncryptionCredentialsResolverBuilder"/>.</returns>
        [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
            Justification = "The X.509 certificate is attached to the server options.")]
        public OpenIddictServerInMemoryEncryptionCredentialsResolverBuilder AddEncryptionCertificate(Stream stream, string? password, X509KeyStorageFlags flags)
        {
            if (stream is null)
            {
                throw new ArgumentNullException(nameof(stream));
            }

            using var buffer = new MemoryStream();
            stream.CopyTo(buffer);

            return AddEncryptionCertificate(new X509Certificate2(buffer.ToArray(), password, flags));
        }

        /// <summary>
        /// Registers an encryption certificate retrieved from the X.509 user or machine store.
        /// </summary>
        /// <param name="thumbprint">The thumbprint of the certificate used to identify it in the X.509 store.</param>
        /// <returns>The <see cref="OpenIddictServerInMemoryEncryptionCredentialsResolverBuilder"/>.</returns>
        public OpenIddictServerInMemoryEncryptionCredentialsResolverBuilder AddEncryptionCertificate(string thumbprint)
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

            return AddEncryptionCertificate(certificate);

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
        /// Registers an encryption certificate retrieved from the specified X.509 store.
        /// </summary>
        /// <param name="thumbprint">The thumbprint of the certificate used to identify it in the X.509 store.</param>
        /// <param name="name">The name of the X.509 store.</param>
        /// <param name="location">The location of the X.509 store.</param>
        /// <returns>The <see cref="OpenIddictServerInMemoryEncryptionCredentialsResolverBuilder"/>.</returns>
        public OpenIddictServerInMemoryEncryptionCredentialsResolverBuilder AddEncryptionCertificate(string thumbprint, StoreName name, StoreLocation location)
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

            return AddEncryptionCertificate(certificate);
        }

        #endregion

        /// <summary>
        /// Constructs the InMemory credential resolver
        /// </summary>
        /// <returns></returns>
        internal OpenIddictServerInMemoryEncryptionCredentialsResolver Build()
        {
            return new OpenIddictServerInMemoryEncryptionCredentialsResolver(_encryptionCredentials);
        }
    }
}
