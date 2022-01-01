/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using Microsoft.Extensions.DependencyInjection;
using OpenIddict.KeyResolvers.InMemory;

namespace Microsoft.Extensions.DependencyInjection;

public static class OpenIddictServerKeyResolversInMemoryExtensions
{
    public static OpenIddictKeyResolversInMemoryBuilder AddInMemoryEncryptionCredentialsManager(this OpenIddictServerBuilder builder)
        => builder.Services.AddInMemoryEncryptionCredentialsManager();

    public static OpenIddictKeyResolversInMemoryBuilder AddInMemorySigningCredentialsManager(this OpenIddictServerBuilder builder)
        => builder.Services.AddInMemorySigningCredentialsManager();
}