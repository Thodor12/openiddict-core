﻿/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;

namespace OpenIddict.Server.AspNetCore;

public static partial class OpenIddictServerAspNetCoreHandlers
{
    public static class Discovery
    {
        public static ImmutableArray<OpenIddictServerHandlerDescriptor> DefaultHandlers { get; } = ImmutableArray.Create([
            /*
             * Configuration request extraction:
             */
            ExtractGetRequest<ExtractConfigurationRequestContext>.Descriptor,

            /*
             * Configuration response processing:
             */
            AttachHttpResponseCode<ApplyConfigurationResponseContext>.Descriptor,
            AttachWwwAuthenticateHeader<ApplyConfigurationResponseContext>.Descriptor,
            ProcessJsonResponse<ApplyConfigurationResponseContext>.Descriptor,

            /*
             * JSON Web Key Set request extraction:
             */
            ExtractGetRequest<ExtractJsonWebKeySetRequestContext>.Descriptor,

            /*
             * JSON Web Key Set response processing:
             */
            AttachHttpResponseCode<ApplyJsonWebKeySetResponseContext>.Descriptor,
            AttachWwwAuthenticateHeader<ApplyJsonWebKeySetResponseContext>.Descriptor,
            ProcessJsonResponse<ApplyJsonWebKeySetResponseContext>.Descriptor
        ]);
    }
}
