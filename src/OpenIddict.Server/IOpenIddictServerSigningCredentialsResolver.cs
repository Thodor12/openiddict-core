using Microsoft.IdentityModel.Tokens;

namespace OpenIddict.Server
{
    public interface IOpenIddictServerSigningCredentialsResolver
    {
        /// <summary>
        /// 
        /// </summary>
        /// <returns></returns>
        public SigningCredentials GetCurrentSigningCredential();

        /// <summary>
        /// Used to return all of the signing credentials.
        /// It is recommended to apply some form of caching and verify which keys are valid
        /// before returning the whole list.
        /// </summary>
        /// <returns>A collection of signing credentials</returns>
        public ICollection<SigningCredentials> GetSigningCredentials();
    }
}
