/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.KeyResolvers.Abstractions;

namespace OpenIddict.KeyResolvers.AzureKeyVault;

internal class OpenIddictAzureKeyVaultEncryptionCredentialsResolver : IOpenIddictEncryptionCredentialsResolver
{
    private readonly IOptionsMonitor<OpenIddictKeyResolversAzureKeyVaultOptions> _optionsMonitor;

    public OpenIddictAzureKeyVaultEncryptionCredentialsResolver(IOptionsMonitor<OpenIddictKeyResolversAzureKeyVaultOptions> optionsMonitor)
        => _optionsMonitor = optionsMonitor;

    public Task<EncryptingCredentials> GetCurrentEncryptionCredentialAsync(CancellationToken cancellationToken)
    {
        //return _encryptionCredentials.First();
        throw new NotImplementedException();
    }

    public Task<ICollection<EncryptingCredentials>> GetEncryptionCredentialsAsync(CancellationToken cancellationToken)
    {
        //return _encryptionCredentials;
        throw new NotImplementedException();
    }
}