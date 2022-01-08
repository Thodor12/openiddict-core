/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using Microsoft.IdentityModel.Tokens;

namespace OpenIddict.KeyResolvers.Abstractions;

/// <summary>
/// The interface used to implement encryption credential resolvers
/// </summary>
public interface IOpenIddictEncryptionCredentialsResolver
{
    /// <summary>
    /// Used to return the currently active <see cref="EncryptingCredentials"/> used for new key operations.
    /// </summary>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>A singular <see cref="EncryptingCredentials"/> for new key operations></returns>
    public Task<EncryptingCredentials> GetCurrentEncryptionCredentialAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Used to return all of the encryption credentials.
    /// It is recommended to apply some form of caching and verify which keys are valid
    /// before returning the whole list.
    /// </summary>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>A collection of encryption credentials</returns>
    public Task<ICollection<EncryptingCredentials>> GetEncryptionCredentialsAsync(CancellationToken cancellationToken = default);
}