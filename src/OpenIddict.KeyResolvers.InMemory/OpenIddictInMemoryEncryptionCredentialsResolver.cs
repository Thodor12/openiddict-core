/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.KeyResolvers.Abstractions;

namespace OpenIddict.KeyResolvers.InMemory;

internal class OpenIddictInMemoryEncryptionCredentialsResolver : IOpenIddictEncryptionCredentialsResolver
{
    private readonly IOptionsMonitor<OpenIddictKeyResolversInMemoryOptions> _optionsMonitor;

    public OpenIddictInMemoryEncryptionCredentialsResolver(IOptionsMonitor<OpenIddictKeyResolversInMemoryOptions> optionsMonitor)
        => _optionsMonitor = optionsMonitor;


    public Task<EncryptingCredentials> GetCurrentEncryptionCredentialAsync(CancellationToken cancellationToken)
    {
        return Task.FromResult(_optionsMonitor.CurrentValue.EncryptionCredentials.First());
    }

    public Task<ICollection<EncryptingCredentials>> GetEncryptionCredentialsAsync(CancellationToken cancellationToken)
    {
        return Task.FromResult<ICollection<EncryptingCredentials>>(_optionsMonitor.CurrentValue.EncryptionCredentials);
    }
}