/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using Microsoft.IdentityModel.Tokens;

namespace OpenIddict.KeyResolvers.InMemory
{
    /// <summary>
    /// Provides the options for the InMemory key resolver
    /// </summary>
    public class OpenIddictKeyResolversInMemoryOptions
    {
        /// <summary>
        /// The list of signing credentials.
        /// </summary>
        public List<SigningCredentials> SigningCredentials { get; } = new List<SigningCredentials>();

        /// <summary>
        /// The list of encrypting credentials.
        /// </summary>
        public List<EncryptingCredentials> EncryptionCredentials { get; } = new List<EncryptingCredentials>();
    }
}
