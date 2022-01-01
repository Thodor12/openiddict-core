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
    /// Extension method to ensure that the key of the signing credentials is a <see cref="AsymmetricSecurityKey"/>
    /// </summary>
    /// <param name="credentials">The signing credentials to verify</param>
    /// <param name="throwException">Whether to throw an exception if the key is not of the right type or return null</param>
    /// <returns>The same signing credentials or null if the key is not an <see cref="AsymmetricSecurityKey"/></returns>
    public static SigningCredentials EnsureIsAsymmetricSecurityKey(this SigningCredentials credentials, bool throwException = false)
    {
        if (credentials.Key is AsymmetricSecurityKey)
        {
            return credentials;
        }
        else
        {
            return throwException ? throw new ArgumentException("The provided signing credentials do not contain an AsymmetricSecurityKey") : null;
        }
    }
}