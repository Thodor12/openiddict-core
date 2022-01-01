/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using Microsoft.Extensions.DependencyInjection;
using OpenIddict.KeyResolvers.Abstractions;

namespace OpenIddict.KeyResolvers.InMemory;

public static class OpenIddictKeyResolversInMemoryExtensions
{
    public static OpenIddictKeyResolversInMemoryBuilder AddInMemoryEncryptionCredentialsManager(this IServiceCollection services)
    {
        services.AddSingleton<IOpenIddictEncryptionCredentialsResolver, OpenIddictInMemoryEncryptionCredentialsResolver>();

        return new OpenIddictKeyResolversInMemoryBuilder(services);
    }

    public static OpenIddictKeyResolversInMemoryBuilder AddInMemorySigningCredentialsManager(this IServiceCollection services)
    {
        services.AddSingleton<IOpenIddictSigningCredentialsResolver, OpenIddictInMemorySigningCredentialsResolver>();

        return new OpenIddictKeyResolversInMemoryBuilder(services);
    }
}