/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using Microsoft.IdentityModel.Tokens;

namespace OpenIddict.KeyResolvers.Abstractions;

public static class IOpenIddictSigningCredentialsExtensions
{
    /// <summary>
    /// Ensure the given encryption key is valid.
    /// It must be present, and if it's an X.509 key the certificate must not be expired.
    /// </summary>
    /// <param name="signingCredentials">The given signing credentials</param>
    /// <returns>The identical signing credentials</returns>
    public static SigningCredentials EnsureValidSigningCredentials(this SigningCredentials signingCredentials)
    {
        ValidateSigningCredentials(new List<SigningCredentials>() { signingCredentials });
        return signingCredentials;
    }

    /// <summary>
    /// Ensure the given collection of keys has at least one valid key.
    /// There must be ast least one key present, and if all the keys are X.509 keys at least one must not be expired.
    /// </summary>
    /// <param name="signingCredentials">The list of given signing credentials</param>
    /// <returns>The identical list of signing credentials</returns>
    public static ICollection<SigningCredentials> EnsureValidSigningCredentials(this ICollection<SigningCredentials> signingCredentials)
    {
        ValidateSigningCredentials(signingCredentials);
        return signingCredentials;
    }

    private static void ValidateSigningCredentials(ICollection<SigningCredentials> signingCredentials)
    {
        // Make sure there's at least one key present
        if (signingCredentials.Count == 0)
        {
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0085));
        }

        // Make sure there's at least one AsymmetricSecurityKey
        if (!signingCredentials.Any(credentials => credentials.Key is AsymmetricSecurityKey))
        {
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0085));
        }

        // If all the registered signing credentials are backed by a X.509 certificate, at least one of them must be valid.
        if (signingCredentials.All(credentials => credentials.Key is X509SecurityKey x509SecurityKey &&
               (x509SecurityKey.Certificate.NotBefore > DateTime.Now || x509SecurityKey.Certificate.NotAfter < DateTime.Now)))
        {
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0087));
        }
    }
}