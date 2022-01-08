/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using Microsoft.IdentityModel.Tokens;

namespace OpenIddict.KeyResolvers.Abstractions;

public static class IOpenIddictEncryptionCredentialsExtensions
{
    /// <summary>
    /// Ensure the given encryption key is valid.
    /// It must be present, and if it's an X.509 key the certificate must not be expired.
    /// </summary>
    /// <param name="encryptionCredentials">The given encryption credentials</param>
    /// <returns>The identical encryption credentials</returns>
    public static EncryptingCredentials EnsureValidEncryptingCredentials(this EncryptingCredentials encryptionCredentials)
    {
        ValidateEncryptionCredentials(new List<EncryptingCredentials>() { encryptionCredentials });
        return encryptionCredentials;
    }

    /// <summary>
    /// Ensure the given collection of keys has at least one valid key.
    /// There must be ast least one key present, and if all the keys are X.509 keys at least one must not be expired.
    /// </summary>
    /// <param name="encryptionCredentials">The list of given encryption credentials</param>
    /// <returns>The identical list of encryption credentials</returns>
    public static ICollection<EncryptingCredentials> EnsureValidEncryptingCredentials(this ICollection<EncryptingCredentials> encryptionCredentials)
    {
        ValidateEncryptionCredentials(encryptionCredentials);
        return encryptionCredentials;
    }

    private static void ValidateEncryptionCredentials(ICollection<EncryptingCredentials> encryptionCredentials)
    {
        // Make sure there's at least one key present
        if (encryptionCredentials.Count == 0)
        {
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0085));
        }

        // If all the registered encryption credentials are backed by a X.509 certificate, at least one of them must be valid.
        if (encryptionCredentials.All(credentials => credentials.Key is X509SecurityKey x509SecurityKey &&
               (x509SecurityKey.Certificate.NotBefore > DateTime.Now || x509SecurityKey.Certificate.NotAfter < DateTime.Now)))
        {
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0087));
        }
    }
}