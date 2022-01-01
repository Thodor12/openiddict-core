/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Validation;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Exposes the necessary methods required to configure the OpenIddict validation services.
/// </summary>
public class OpenIddictValidationBuilder
{
    /// <summary>
    /// Initializes a new instance of <see cref="OpenIddictValidationBuilder"/>.
    /// </summary>
    /// <param name="services">The services collection.</param>
    public OpenIddictValidationBuilder(IServiceCollection services)
        => Services = services ?? throw new ArgumentNullException(nameof(services));

    /// <summary>
    /// Gets the services collection.
    /// </summary>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public IServiceCollection Services { get; }

    /// <summary>
    /// Registers an event handler using the specified configuration delegate.
    /// </summary>
    /// <typeparam name="TContext">The event context type.</typeparam>
    /// <param name="configuration">The configuration delegate.</param>
    /// <returns>The <see cref="OpenIddictValidationBuilder"/>.</returns>
    [EditorBrowsable(EditorBrowsableState.Advanced)]
    public OpenIddictValidationBuilder AddEventHandler<TContext>(
        Action<OpenIddictValidationHandlerDescriptor.Builder<TContext>> configuration)
        where TContext : OpenIddictValidationEvents.BaseContext
    {
        if (configuration is null)
        {
            throw new ArgumentNullException(nameof(configuration));
        }

        // Note: handlers registered using this API are assumed to be custom handlers by default.
        var builder = OpenIddictValidationHandlerDescriptor.CreateBuilder<TContext>()
            .SetType(OpenIddictValidationHandlerType.Custom);

        configuration(builder);

        return AddEventHandler(builder.Build());
    }

    /// <summary>
    /// Registers an event handler using the specified descriptor.
    /// </summary>
    /// <param name="descriptor">The handler descriptor.</param>
    /// <returns>The <see cref="OpenIddictValidationBuilder"/>.</returns>
    [EditorBrowsable(EditorBrowsableState.Advanced)]
    public OpenIddictValidationBuilder AddEventHandler(OpenIddictValidationHandlerDescriptor descriptor)
    {
        if (descriptor is null)
        {
            throw new ArgumentNullException(nameof(descriptor));
        }

        // Register the handler in the services collection.
        Services.Add(descriptor.ServiceDescriptor);

        return Configure(options => options.Handlers.Add(descriptor));
    }

    /// <summary>
    /// Removes the event handler that matches the specified descriptor.
    /// </summary>
    /// <param name="descriptor">The descriptor corresponding to the handler to remove.</param>
    /// <returns>The <see cref="OpenIddictValidationBuilder"/>.</returns>
    [EditorBrowsable(EditorBrowsableState.Advanced)]
    public OpenIddictValidationBuilder RemoveEventHandler(OpenIddictValidationHandlerDescriptor descriptor)
    {
        if (descriptor is null)
        {
            throw new ArgumentNullException(nameof(descriptor));
        }

        Services.RemoveAll(descriptor.ServiceDescriptor.ServiceType);

        Services.PostConfigure<OpenIddictValidationOptions>(options =>
        {
            for (var index = options.Handlers.Count - 1; index >= 0; index--)
            {
                if (options.Handlers[index].ServiceDescriptor.ServiceType == descriptor.ServiceDescriptor.ServiceType)
                {
                    options.Handlers.RemoveAt(index);
                }
            }
        });

        return this;
    }

    /// <summary>
    /// Amends the default OpenIddict validation configuration.
    /// </summary>
    /// <param name="configuration">The delegate used to configure the OpenIddict options.</param>
    /// <remarks>This extension can be safely called multiple times.</remarks>
    /// <returns>The <see cref="OpenIddictValidationBuilder"/>.</returns>
    public OpenIddictValidationBuilder Configure(Action<OpenIddictValidationOptions> configuration)
    {
        if (configuration is null)
        {
            throw new ArgumentNullException(nameof(configuration));
        }

        Services.Configure(configuration);

        return this;
    }

    /// <summary>
    /// Registers the specified values as valid audiences. Setting the audiences is recommended
    /// when the authorization server issues access tokens for multiple distinct resource servers.
    /// </summary>
    /// <param name="audiences">The audiences valid for this resource server.</param>
    /// <returns>The <see cref="OpenIddictValidationBuilder"/>.</returns>
    public OpenIddictValidationBuilder AddAudiences(params string[] audiences)
    {
        if (audiences is null)
        {
            throw new ArgumentNullException(nameof(audiences));
        }

        if (audiences.Any(audience => string.IsNullOrEmpty(audience)))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0123), nameof(audiences));
        }

        return Configure(options => options.Audiences.UnionWith(audiences));
    }

    /// <summary>
    /// Enables authorization validation so that a database call is made for each API request
    /// to ensure the authorization associated with the access token is still valid.
    /// Note: enabling this option may have an impact on performance and
    /// can only be used with an OpenIddict-based authorization server.
    /// </summary>
    /// <returns>The <see cref="OpenIddictValidationBuilder"/>.</returns>
    public OpenIddictValidationBuilder EnableAuthorizationEntryValidation()
        => Configure(options => options.EnableAuthorizationEntryValidation = true);

    /// <summary>
    /// Enables token validation so that a database call is made for each API request
    /// to ensure the token entry associated with the access token is still valid.
    /// Note: enabling this option may have an impact on performance but is required
    /// when the OpenIddict server is configured to use reference tokens.
    /// </summary>
    /// <returns>The <see cref="OpenIddictValidationBuilder"/>.</returns>
    public OpenIddictValidationBuilder EnableTokenEntryValidation()
        => Configure(options => options.EnableTokenEntryValidation = true);

    /// <summary>
    /// Sets a static OpenID Connect server configuration, that will be used to
    /// resolve the metadata/introspection endpoints and the issuer signing keys.
    /// </summary>
    /// <param name="configuration">The server configuration.</param>
    /// <returns>The <see cref="OpenIddictValidationBuilder"/>.</returns>
    public OpenIddictValidationBuilder SetConfiguration(OpenIdConnectConfiguration configuration)
    {
        if (configuration is null)
        {
            throw new ArgumentNullException(nameof(configuration));
        }

        return Configure(options => options.Configuration = configuration);
    }

    /// <summary>
    /// Sets the client identifier client_id used when communicating
    /// with the remote authorization server (e.g for introspection).
    /// </summary>
    /// <param name="identifier">The client identifier.</param>
    /// <returns>The <see cref="OpenIddictValidationBuilder"/>.</returns>
    public OpenIddictValidationBuilder SetClientId(string identifier)
    {
        if (string.IsNullOrEmpty(identifier))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0124), nameof(identifier));
        }

        return Configure(options => options.ClientId = identifier);
    }

    /// <summary>
    /// Sets the client identifier client_secret used when communicating
    /// with the remote authorization server (e.g for introspection).
    /// </summary>
    /// <param name="secret">The client secret.</param>
    /// <returns>The <see cref="OpenIddictValidationBuilder"/>.</returns>
    public OpenIddictValidationBuilder SetClientSecret(string secret)
    {
        if (string.IsNullOrEmpty(secret))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0125), nameof(secret));
        }

        return Configure(options => options.ClientSecret = secret);
    }

    /// <summary>
    /// Sets the issuer address, which is used to determine the actual location of the
    /// OAuth 2.0/OpenID Connect configuration document when using provider discovery.
    /// </summary>
    /// <param name="address">The issuer address.</param>
    /// <returns>The <see cref="OpenIddictValidationBuilder"/>.</returns>
    public OpenIddictValidationBuilder SetIssuer(Uri address)
    {
        if (address is null)
        {
            throw new ArgumentNullException(nameof(address));
        }

        return Configure(options => options.Issuer = address);
    }

    /// <summary>
    /// Sets the issuer address, which is used to determine the actual location of the
    /// OAuth 2.0/OpenID Connect configuration document when using provider discovery.
    /// </summary>
    /// <param name="address">The issuer address.</param>
    /// <returns>The <see cref="OpenIddictValidationBuilder"/>.</returns>
    public OpenIddictValidationBuilder SetIssuer(string address)
    {
        if (string.IsNullOrEmpty(address))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0126), nameof(address));
        }

        if (!Uri.TryCreate(address, UriKind.Absolute, out Uri? uri) || !uri.IsWellFormedOriginalString())
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0127), nameof(address));
        }

        return SetIssuer(uri);
    }

    /// <summary>
    /// Configures OpenIddict to use introspection instead of local/direct validation.
    /// </summary>
    /// <returns>The <see cref="OpenIddictValidationBuilder"/>.</returns>
    public OpenIddictValidationBuilder UseIntrospection()
        => Configure(options => options.ValidationType = OpenIddictValidationType.Introspection);

    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals(object? obj) => base.Equals(obj);

    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode() => base.GetHashCode();

    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override string? ToString() => base.ToString();
}
