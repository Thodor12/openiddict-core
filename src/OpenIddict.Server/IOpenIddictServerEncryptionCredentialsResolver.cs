using Microsoft.IdentityModel.Tokens;

namespace OpenIddict.Server
{
    public interface IOpenIddictServerEncryptionCredentialsResolver
    {
        /// <summary>
        /// 
        /// </summary>
        /// <returns></returns>
        public EncryptingCredentials GetCurrentEncryptionCredential();

        /// <summary>
        /// Used to return all of the encryption credentials.
        /// It is recommended to apply some form of caching and verify which keys are valid
        /// before returning the whole list.
        /// </summary>
        /// <returns>A collection of encryption credentials</returns>
        public ICollection<EncryptingCredentials> GetEncryptionCredentials();
    }
}
