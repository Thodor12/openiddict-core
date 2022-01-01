/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using Microsoft.Extensions.Options;

namespace OpenIddict.Server;

/// <summary>
/// Contains the methods required to ensure that the OpenIddict server configuration is valid.
/// </summary>
public class OpenIddictServerConfiguration : IPostConfigureOptions<OpenIddictServerOptions>
{
    /// <summary>
    /// Populates the default OpenIddict server options and ensures
    /// that the configuration is in a consistent and valid state.
    /// </summary>
    /// <param name="name">The name of the options instance to configure, if applicable.</param>
    /// <param name="options">The options instance to initialize.</param>
    public void PostConfigure(string name, OpenIddictServerOptions options)
    {
        if (options is null)
        {
            throw new ArgumentNullException(nameof(options));
        }

        // Explicitly disable all the features that are implicitly excluded when the degraded mode is active.
        if (options.EnableDegradedMode)
        {
            options.DisableAuthorizationStorage = options.DisableTokenStorage = options.DisableRollingRefreshTokens = true;
            options.IgnoreEndpointPermissions = options.IgnoreGrantTypePermissions = true;
            options.IgnoreResponseTypePermissions = options.IgnoreScopePermissions = true;
            options.UseReferenceAccessTokens = options.UseReferenceRefreshTokens = false;
        }

        // Explicitly disable rolling refresh tokens when token storage is disabled.
        if (options.DisableTokenStorage)
        {
            options.DisableRollingRefreshTokens = true;
        }

        if (options.JsonWebTokenHandler is null)
        {
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0075));
        }

        // Ensure at least one flow has been enabled.
        if (options.GrantTypes.Count == 0)
        {
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0076));
        }

        var addresses = options.AuthorizationEndpointUris.Distinct()
            .Concat(options.ConfigurationEndpointUris.Distinct())
            .Concat(options.CryptographyEndpointUris.Distinct())
            .Concat(options.DeviceEndpointUris.Distinct())
            .Concat(options.IntrospectionEndpointUris.Distinct())
            .Concat(options.LogoutEndpointUris.Distinct())
            .Concat(options.RevocationEndpointUris.Distinct())
            .Concat(options.TokenEndpointUris.Distinct())
            .Concat(options.UserinfoEndpointUris.Distinct())
            .Concat(options.VerificationEndpointUris.Distinct())
            .ToList();

        // Ensure endpoint addresses are unique across endpoints.
        if (addresses.Count != addresses.Distinct().Count())
        {
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0285));
        }

        // Ensure the authorization endpoint has been enabled when
        // the authorization code or implicit grants are supported.
        if (options.AuthorizationEndpointUris.Count == 0 && (options.GrantTypes.Contains(GrantTypes.AuthorizationCode) ||
                                                             options.GrantTypes.Contains(GrantTypes.Implicit)))
        {
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0077));
        }

        // Ensure the device endpoint has been enabled when the device grant is supported.
        if (options.DeviceEndpointUris.Count == 0 && options.GrantTypes.Contains(GrantTypes.DeviceCode))
        {
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0078));
        }

        // Ensure the token endpoint has been enabled when the authorization code,
        // client credentials, device, password or refresh token grants are supported.
        if (options.TokenEndpointUris.Count == 0 && (options.GrantTypes.Contains(GrantTypes.AuthorizationCode) ||
                                                     options.GrantTypes.Contains(GrantTypes.ClientCredentials) ||
                                                     options.GrantTypes.Contains(GrantTypes.DeviceCode) ||
                                                     options.GrantTypes.Contains(GrantTypes.Password) ||
                                                     options.GrantTypes.Contains(GrantTypes.RefreshToken)))
        {
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0079));
        }

        // Ensure the verification endpoint has been enabled when the device grant is supported.
        if (options.VerificationEndpointUris.Count == 0 && options.GrantTypes.Contains(GrantTypes.DeviceCode))
        {
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0080));
        }

        // Ensure the device grant is allowed when the device endpoint is enabled.
        if (options.DeviceEndpointUris.Count > 0 && !options.GrantTypes.Contains(GrantTypes.DeviceCode))
        {
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0084));
        }

        // Ensure the grant types/response types configuration is consistent.
        foreach (var type in options.ResponseTypes)
        {
            var types = new HashSet<string>(type.Split(Separators.Space, StringSplitOptions.RemoveEmptyEntries), StringComparer.Ordinal);
            if (types.Contains(ResponseTypes.Code) && !options.GrantTypes.Contains(GrantTypes.AuthorizationCode))
            {
                throw new InvalidOperationException(SR.FormatID0281(ResponseTypes.Code));
            }

            if (types.Contains(ResponseTypes.IdToken) && !options.GrantTypes.Contains(GrantTypes.Implicit))
            {
                throw new InvalidOperationException(SR.FormatID0282(ResponseTypes.IdToken));
            }

            if (types.Contains(ResponseTypes.Token) && !options.GrantTypes.Contains(GrantTypes.Implicit))
            {
                throw new InvalidOperationException(SR.FormatID0282(ResponseTypes.Token));
            }
        }

        // Ensure reference tokens support was not enabled when token storage is disabled.
        if (options.DisableTokenStorage && (options.UseReferenceAccessTokens || options.UseReferenceRefreshTokens))
        {
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0083));
        }

        if (options.EnableDegradedMode)
        {
            // If the degraded mode was enabled, ensure custom validation handlers
            // have been registered for the endpoints that require manual validation.

            if (options.AuthorizationEndpointUris.Count != 0 && !options.Handlers.Any(
                descriptor => descriptor.ContextType == typeof(ValidateAuthorizationRequestContext) &&
                              descriptor.Type == OpenIddictServerHandlerType.Custom &&
                              descriptor.FilterTypes.All(type => !typeof(RequireDegradedModeDisabled).IsAssignableFrom(type))))
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0089));
            }

            if (options.DeviceEndpointUris.Count != 0 && !options.Handlers.Any(
                descriptor => descriptor.ContextType == typeof(ValidateDeviceRequestContext) &&
                              descriptor.Type == OpenIddictServerHandlerType.Custom &&
                              descriptor.FilterTypes.All(type => !typeof(RequireDegradedModeDisabled).IsAssignableFrom(type))))
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0090));
            }

            if (options.IntrospectionEndpointUris.Count != 0 && !options.Handlers.Any(
                descriptor => descriptor.ContextType == typeof(ValidateIntrospectionRequestContext) &&
                              descriptor.Type == OpenIddictServerHandlerType.Custom &&
                              descriptor.FilterTypes.All(type => !typeof(RequireDegradedModeDisabled).IsAssignableFrom(type))))
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0091));
            }

            if (options.LogoutEndpointUris.Count != 0 && !options.Handlers.Any(
                descriptor => descriptor.ContextType == typeof(ValidateLogoutRequestContext) &&
                              descriptor.Type == OpenIddictServerHandlerType.Custom &&
                              descriptor.FilterTypes.All(type => !typeof(RequireDegradedModeDisabled).IsAssignableFrom(type))))
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0092));
            }

            if (options.RevocationEndpointUris.Count != 0 && !options.Handlers.Any(
                descriptor => descriptor.ContextType == typeof(ValidateRevocationRequestContext) &&
                              descriptor.Type == OpenIddictServerHandlerType.Custom &&
                              descriptor.FilterTypes.All(type => !typeof(RequireDegradedModeDisabled).IsAssignableFrom(type))))
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0093));
            }

            if (options.TokenEndpointUris.Count != 0 && !options.Handlers.Any(
                descriptor => descriptor.ContextType == typeof(ValidateTokenRequestContext) &&
                              descriptor.Type == OpenIddictServerHandlerType.Custom &&
                              descriptor.FilterTypes.All(type => !typeof(RequireDegradedModeDisabled).IsAssignableFrom(type))))
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0094));
            }

            if (options.VerificationEndpointUris.Count != 0 && !options.Handlers.Any(
                descriptor => descriptor.ContextType == typeof(ValidateVerificationRequestContext) &&
                              descriptor.Type == OpenIddictServerHandlerType.Custom &&
                              descriptor.FilterTypes.All(type => !typeof(RequireDegradedModeDisabled).IsAssignableFrom(type))))
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0095));
            }

            // If the degraded mode was enabled, ensure custom validation/generation handlers
            // have been registered to deal with device/user codes validation and generation.

            if (options.GrantTypes.Contains(GrantTypes.DeviceCode))
            {
                if (!options.Handlers.Any(
                    descriptor => descriptor.ContextType == typeof(ValidateTokenContext) &&
                                  descriptor.Type == OpenIddictServerHandlerType.Custom &&
                                  descriptor.FilterTypes.All(type => !typeof(RequireDegradedModeDisabled).IsAssignableFrom(type))))
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0096));
                }

                if (!options.Handlers.Any(
                    descriptor => descriptor.ContextType == typeof(GenerateTokenContext) &&
                                  descriptor.Type == OpenIddictServerHandlerType.Custom &&
                                  descriptor.FilterTypes.All(type => !typeof(RequireDegradedModeDisabled).IsAssignableFrom(type))))
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0097));
                }
            }
        }

        // Sort the handlers collection using the order associated with each handler.
        options.Handlers.Sort((left, right) => left.Order.CompareTo(right.Order));
    }
}
