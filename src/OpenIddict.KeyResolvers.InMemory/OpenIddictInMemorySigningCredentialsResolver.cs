/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.KeyResolvers.Abstractions;

namespace OpenIddict.KeyResolvers.InMemory;

internal class OpenIddictInMemorySigningCredentialsResolver : IOpenIddictSigningCredentialsResolver
{
    private readonly IOptionsMonitor<OpenIddictKeyResolversInMemoryOptions> _optionsMonitor;

    public OpenIddictInMemorySigningCredentialsResolver(IOptionsMonitor<OpenIddictKeyResolversInMemoryOptions> optionsMonitor)
        => _optionsMonitor = optionsMonitor;

    public Task<SigningCredentials> GetCurrentSigningCredentialAsync(CancellationToken cancellationToken)
    {
        return Task.FromResult(_optionsMonitor.CurrentValue.SigningCredentials.First());
    }

    public Task<SigningCredentials> GetCurrentSigningCredentialsWithAssymetricKeyAsync(CancellationToken cancellationToken)
    {
        return Task.FromResult(_optionsMonitor.CurrentValue.SigningCredentials.First(f => f.Key is AsymmetricSecurityKey));
    }

    public Task<ICollection<SigningCredentials>> GetSigningCredentialsAsync(CancellationToken cancellationToken)
    {
        return Task.FromResult<ICollection<SigningCredentials>>(_optionsMonitor.CurrentValue.SigningCredentials);
    }
}