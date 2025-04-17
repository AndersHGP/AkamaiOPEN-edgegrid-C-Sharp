using System.IO;
using System.Net.Http;
using System.Threading.Tasks;

namespace Akamai.EdgeGrid.Auth
{
    /// <summary>
    /// Interface describing a request signer that signs service requests.
    ///
    /// Author: colinb@akamai.com  (Colin Bendell)
    /// </summary>
    interface IRequestSigner
    {
        /// <summary>
        /// Signs a request with the client credential.
        /// </summary>
        /// <param name="request">The HTTP request message to sign.</param>
        /// <param name="credential">The credential used in the signing.</param>
        /// <param name="uploadStream">The optional stream to upload.</param>
        void Sign(HttpRequestMessage request, ClientCredential credential, Stream uploadStream = null);

        /// <summary>
        /// Signs and executes a request with the client credential.
        /// </summary>
        /// <param name="request">The HTTP request message to sign and execute.</param>
        /// <param name="credential">The credential used in the signing.</param>
        /// <param name="uploadStream">The optional stream to upload.</param>
        /// <returns>The HTTP response message from the executed request.</returns>
        Task<HttpResponseMessage> ExecuteAsync(HttpRequestMessage request, ClientCredential credential, Stream uploadStream = null);
    }
}