/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using Microsoft.Extensions.DependencyInjection;
using OpenIddict.KeyResolvers.Abstractions;

namespace OpenIddict.KeyResolvers.AzureKeyVault;

public static class OpenIddictKeyResolversAzureKeyVaultExtensions
{
    public static OpenIddictKeyResolversAzureKeyVaultBuilder AddAzureKeyVaultEncryptionCredentialsManager(this IServiceCollection services)
    {
        services.AddSingleton<IOpenIddictEncryptionCredentialsResolver, OpenIddictAzureKeyVaultEncryptionCredentialsResolver>();

        return new OpenIddictKeyResolversAzureKeyVaultBuilder(services);
    }

    public static OpenIddictKeyResolversAzureKeyVaultBuilder AddAzureKeyVaultSigningCredentialsManager(this IServiceCollection services)
    {
        services.AddSingleton<IOpenIddictSigningCredentialsResolver, OpenIddictAzureKeyVaultSigningCredentialsResolver>();

        return new OpenIddictKeyResolversAzureKeyVaultBuilder(services);
    }
}