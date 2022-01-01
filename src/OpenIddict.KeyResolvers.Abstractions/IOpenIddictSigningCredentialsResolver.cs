/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using Microsoft.IdentityModel.Tokens;

namespace OpenIddict.KeyResolvers.Abstractions;

public interface IOpenIddictSigningCredentialsResolver
{
    /// <summary>
    /// Used to return the currently active <see cref="SigningCredentials"/> used for new key operations.
    /// </summary>
    /// <param name="cancellationToken"></param>
    /// <returns>A singular <see cref="SigningCredentials"/> for new key operations</returns>
    public Task<SigningCredentials> GetCurrentSigningCredentialAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Similar to <see cref="GetCurrentSigningCredentialAsync"/> however this method
    /// must return a <see cref="SigningCredentials"/> where it's <see cref="SigningCredentials.Key"/>
    /// is an <see cref="AsymmetricSecurityKey"/>.
    /// </summary>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    public Task<SigningCredentials> GetCurrentSigningCredentialsWithAssymetricKeyAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Used to return all of the <see cref="SigningCredentials"/>.
    /// It is recommended to apply some form of caching and verify which keys are valid
    /// before returning the whole list.
    /// </summary>
    /// <param name="cancellationToken"></param>
    /// <returns>A collection of signing credentials</returns>
    public Task<ICollection<SigningCredentials>> GetSigningCredentialsAsync(CancellationToken cancellationToken = default);
}
