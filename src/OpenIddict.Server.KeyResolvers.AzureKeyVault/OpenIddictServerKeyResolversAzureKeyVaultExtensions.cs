/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using Microsoft.Extensions.DependencyInjection;
using OpenIddict.KeyResolvers.AzureKeyVault;

namespace Microsoft.Extensions.DependencyInjection;

public static class OpenIddictServerKeyResolversAzureKeyVaultExtensions
{
    public static OpenIddictKeyResolversAzureKeyVaultBuilder AddAzureKeyVaultEncryptionCredentialsManager(this OpenIddictServerBuilder builder)
        => builder.Services.AddAzureKeyVaultEncryptionCredentialsManager();

    public static OpenIddictKeyResolversAzureKeyVaultBuilder AddAzureKeyVaultSigningCredentialsManager(this OpenIddictServerBuilder builder)
        => builder.Services.AddAzureKeyVaultSigningCredentialsManager();
}