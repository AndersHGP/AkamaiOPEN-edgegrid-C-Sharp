using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Akamai.Utils;

namespace Akamai.EdgeGrid.Auth
{
    /// <summary>
    /// Handles signing HTTP requests using the EdgeGrid V1 authentication scheme.
    /// </summary>
    public class EdgeGridV1Signer : IRequestSigner
    {
        private readonly IHttpClientFactory _httpClientFactory;

        public const string AuthorizationHeader = "Authorization";

        public IReadOnlyList<string> HeadersToInclude { get; }
        public long? MaxBodyHashSize { get; }

        /// <summary>
        /// Initializes a new instance of the EdgeGridV1Signer class.
        /// </summary>
        /// <param name="httpClientFactory">Factory for creating HttpClient instances.</param>
        /// <param name="headers">Headers to include in the signature.</param>
        /// <param name="maxBodyHashSize">Maximum size of the request body to hash.</param>
        public EdgeGridV1Signer(IHttpClientFactory httpClientFactory, IEnumerable<string>? headers = null, long? maxBodyHashSize = 2048)
        {
            _httpClientFactory = httpClientFactory ?? throw new ArgumentNullException(nameof(httpClientFactory));
            HeadersToInclude = headers?.ToList() ?? new List<string>();
            MaxBodyHashSize = maxBodyHashSize;
        }

        /// <summary>
        /// Generates the authentication data string for the request.
        /// </summary>
        /// <param name="credential">Client credentials for signing.</param>
        /// <param name="timestamp">Timestamp for the request.</param>
        /// <returns>Authentication data string.</returns>
        private string GetAuthDataValue(ClientCredential credential, DateTime timestamp)
        {
            var nonce = Guid.NewGuid();
            return $"EG1-HMAC-SHA256 client_token={credential.ClientToken};access_token={credential.AccessToken};timestamp={timestamp:yyyyMMddTHH:mm:ssZ};nonce={nonce:N};";
        }

        /// <summary>
        /// Constructs the request data string to be signed.
        /// </summary>
        /// <param name="request">The HTTP request message.</param>
        /// <param name="requestStream">Optional request body stream.</param>
        /// <returns>Request data string.</returns>
        private string GetRequestData(HttpRequestMessage request, Stream? requestStream = null)
        {
            var method = request.Method.Method.ToUpperInvariant();
            var headers = GetRequestHeaders(request.Headers);
            var bodyHash = method == "POST" ? GetRequestStreamHash(requestStream) : string.Empty;

            return $"{method}\t{request.RequestUri!.Scheme}\t{request.RequestUri.Host}\t{request.RequestUri.PathAndQuery}\t{headers}\t{bodyHash}\t";
        }

        /// <summary>
        /// Retrieves the headers to include in the signature.
        /// </summary>
        /// <param name="headers">HTTP headers from the request.</param>
        /// <returns>Formatted headers string.</returns>
        private string GetRequestHeaders(System.Net.Http.Headers.HttpHeaders headers)
        {
            if (headers == null || !HeadersToInclude.Any()) return string.Empty;

            var headerString = new StringBuilder();
            foreach (var header in HeadersToInclude)
            {
                if (headers.TryGetValues(header, out var values))
                {
                    var value = string.Join(" ", values).Trim();
                    headerString.Append($"{header}:{Regex.Replace(value, "\\s+", " ", RegexOptions.Compiled)}\t");
                }
            }
            return headerString.ToString();
        }

        /// <summary>
        /// Computes the hash of the request body stream.
        /// </summary>
        /// <param name="requestStream">The request body stream.</param>
        /// <returns>Base64-encoded hash of the stream.</returns>
        private string GetRequestStreamHash(Stream? requestStream)
        {
            if (requestStream == null) return string.Empty;

            if (!requestStream.CanRead || !requestStream.CanSeek)
                throw new IOException("Stream must be readable and seekable!");

            var streamHash = requestStream.ComputeHash(ChecksumAlgorithm.SHA256, MaxBodyHashSize).ToBase64();
            requestStream.Seek(0, SeekOrigin.Begin);
            return streamHash;
        }

        /// <summary>
        /// Generates the authorization header value.
        /// </summary>
        /// <param name="credential">Client credentials for signing.</param>
        /// <param name="timestamp">Timestamp for the request.</param>
        /// <param name="authData">Authentication data string.</param>
        /// <param name="requestData">Request data string.</param>
        /// <returns>Authorization header value.</returns>
        private string GetAuthorizationHeaderValue(ClientCredential credential, DateTime timestamp, string authData, string requestData)
        {
            var signingKey = timestamp.ToString("yyyyMMddTHH:mm:ssZ").ToByteArray()
                .ComputeKeyedHash(credential.Secret, KeyedHashAlgorithm.HMACSHA256)
                .ToBase64();

            var authSignature = $"{requestData}{authData}".ToByteArray()
                .ComputeKeyedHash(signingKey, KeyedHashAlgorithm.HMACSHA256)
                .ToBase64();

            return $"{authData}signature={authSignature}";
        }

        /// <summary>
        /// Signs the HTTP request by adding the authorization header.
        /// </summary>
        /// <param name="request">The HTTP request message.</param>
        /// <param name="credential">Client credentials for signing.</param>
        /// <param name="uploadStream">Optional request body stream.</param>
        public void Sign(HttpRequestMessage request, ClientCredential credential, Stream? uploadStream = null)
        {
            ArgumentNullException.ThrowIfNull(request, nameof(request));
            ArgumentNullException.ThrowIfNull(credential, nameof(credential));

            var timestamp = DateTime.UtcNow;
            var authData = GetAuthDataValue(credential, timestamp);
            var requestData = GetRequestData(request, uploadStream);
            var authorizationHeader = GetAuthorizationHeaderValue(credential, timestamp, authData, requestData);

            if (!request.Headers.Contains(AuthorizationHeader))
            {
                request.Headers.Add(AuthorizationHeader, authorizationHeader);
            }
        }

        /// <summary>
        /// Executes the HTTP request with the signed authorization header.
        /// </summary>
        /// <param name="request">The HTTP request message.</param>
        /// <param name="credential">Client credentials for signing.</param>
        /// <param name="uploadStream">Optional request body stream.</param>
        /// <returns>The HTTP response message.</returns>
        public async Task<HttpResponseMessage> ExecuteAsync(HttpRequestMessage request, ClientCredential credential, Stream? uploadStream = null)
        {
            ArgumentNullException.ThrowIfNull(request, nameof(request));
            ArgumentNullException.ThrowIfNull(credential, nameof(credential));

            Sign(request, credential, uploadStream);

            if (uploadStream != null && request.Method == HttpMethod.Post)
            {
                request.Content = new StreamContent(uploadStream)
                {
                    Headers = { ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/json") }
                };
            }

            var client = _httpClientFactory.CreateClient();
            return await client.SendAsync(request).ConfigureAwait(false);
        }
    }
}