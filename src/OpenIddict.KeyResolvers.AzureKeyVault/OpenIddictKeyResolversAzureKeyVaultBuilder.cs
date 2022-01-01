/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using OpenIddict.KeyResolvers.AzureKeyVault;
using System.ComponentModel;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Exposes the necessary methods required to configure the
/// OpenIddict Azure Key Vault integration.
/// </summary>
public class OpenIddictKeyResolversAzureKeyVaultBuilder
{
    /// <summary>
    /// Initializes a new instance of <see cref="OpenIddictKeyResolversAzureKeyVaultBuilder"/>.
    /// </summary>
    /// <param name="services">The services collection.</param>
    public OpenIddictKeyResolversAzureKeyVaultBuilder(IServiceCollection services)
        => Services = services ?? throw new ArgumentNullException(nameof(services));

    /// <summary>
    /// Gets the services collection.
    /// </summary>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public IServiceCollection Services { get; }

    /// <summary>
    /// Amends the default OpenIddict Azure Key Vault key resolver configuration.
    /// </summary>
    /// <param name="configuration">The delegate used to configure the OpenIddict options.</param>
    /// <remarks>This extension can be safely called multiple times.</remarks>
    /// <returns>The <see cref="OpenIddictKeyResolversAzureKeyVaultBuilder"/>.</returns>
    public OpenIddictKeyResolversAzureKeyVaultBuilder Configure(Action<OpenIddictKeyResolversAzureKeyVaultOptions> configuration)
    {
        if (configuration is null)
        {
            throw new ArgumentNullException(nameof(configuration));
        }

        Services.Configure(configuration);

        return this;
    }
}