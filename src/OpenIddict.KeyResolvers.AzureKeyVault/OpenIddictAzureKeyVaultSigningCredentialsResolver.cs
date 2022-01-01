/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.KeyResolvers.Abstractions;

namespace OpenIddict.KeyResolvers.AzureKeyVault;

internal class OpenIddictAzureKeyVaultSigningCredentialsResolver : IOpenIddictSigningCredentialsResolver
{
    private readonly IOptionsMonitor<OpenIddictKeyResolversAzureKeyVaultOptions> _optionsMonitor;

    public OpenIddictAzureKeyVaultSigningCredentialsResolver(IOptionsMonitor<OpenIddictKeyResolversAzureKeyVaultOptions> optionsMonitor)
        => _optionsMonitor = optionsMonitor;

    public Task<SigningCredentials> GetCurrentSigningCredentialAsync(CancellationToken cancellationToken)
    {
        //return _optionsMonitor.CurrentValue.SigningCredentials.First();
        throw new NotImplementedException();
    }

    public Task<SigningCredentials> GetCurrentSigningCredentialsWithAssymetricKeyAsync(CancellationToken cancellationToken)
    {
        //return _optionsMonitor.CurrentValue.SigningCredentials.First(f => f.Key is AsymmetricSecurityKey);
        throw new NotImplementedException();
    }

    public Task<ICollection<SigningCredentials>> GetSigningCredentialsAsync(CancellationToken cancellationToken)
    {
        //return _optionsMonitor.CurrentValue.SigningCredentials;
        throw new NotImplementedException();
    }
}