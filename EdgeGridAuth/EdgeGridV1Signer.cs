using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Akamai.Utils;

namespace Akamai.EdgeGrid.Auth
{
    public class EdgeGridV1Signer : IRequestSigner
    {
        public const string AuthorizationHeader = "Authorization";

        internal IList<string> HeadersToInclude { get; private set; }
        internal long? MaxBodyHashSize { get; private set; }

        public EdgeGridV1Signer(IList<string> headers = null, long? maxBodyHashSize = 2048)
        {
            this.HeadersToInclude = headers ?? new List<string>();
            this.MaxBodyHashSize = maxBodyHashSize;
        }

        internal string GetAuthDataValue(ClientCredential credential, DateTime timestamp)
        {
            Guid nonce = Guid.NewGuid();
            return string.Format("EG1-HMAC-SHA256 client_token={0};access_token={1};timestamp={2};nonce={3};",
                credential.ClientToken,
                credential.AccessToken,
                timestamp.ToString("yyyyMMddTHH:mm:ssZ"),
                nonce.ToString().ToLower());
        }

        internal string GetRequestData(HttpRequestMessage request, Stream requestStream = null)
        {
            string method = request.Method.Method;
            string headers = GetRequestHeaders(request.Headers);
            string bodyHash = method == "POST" ? GetRequestStreamHash(requestStream) : "";

            return string.Format("{0}\t{1}\t{2}\t{3}\t{4}\t{5}\t",
                method.ToUpper(),
                request.RequestUri.Scheme,
                request.RequestUri.Host,
                request.RequestUri.PathAndQuery,
                headers,
                bodyHash);
        }

        internal string GetRequestHeaders(System.Net.Http.Headers.HttpHeaders headers)
        {
            if (headers == null) return string.Empty;

            StringBuilder headerString = new StringBuilder();
            foreach (var header in this.HeadersToInclude)
            {
                if (headers.TryGetValues(header, out var values))
                {
                    string value = string.Join(" ", values).Trim();
                    headerString.AppendFormat("{0}:{1}\t", header, Regex.Replace(value, "\\s+", " ", RegexOptions.Compiled));
                }
            }
            return headerString.ToString();
        }

        internal string GetRequestStreamHash(Stream requestStream)
        {
            if (requestStream == null) return string.Empty;

            if (!requestStream.CanRead)
                throw new IOException("Cannot read stream to compute hash");

            if (!requestStream.CanSeek)
                throw new IOException("Stream must be seekable!");

            string streamHash = requestStream.ComputeHash(ChecksumAlgorithm.SHA256, MaxBodyHashSize).ToBase64();
            requestStream.Seek(0, SeekOrigin.Begin);
            return streamHash;
        }

        internal string GetAuthorizationHeaderValue(ClientCredential credential, DateTime timestamp, string authData, string requestData)
        {
            string signingKey = timestamp.ToString("yyyyMMddTHH:mm:ssZ").ToByteArray().ComputeKeyedHash(credential.Secret, KeyedHashAlgorithm.HMACSHA256).ToBase64();
            string authSignature = string.Format("{0}{1}", requestData, authData).ToByteArray().ComputeKeyedHash(signingKey, KeyedHashAlgorithm.HMACSHA256).ToBase64();
            return string.Format("{0}signature={1}", authData, authSignature);
        }

        public void Sign(HttpRequestMessage request, ClientCredential credential, Stream uploadStream = null)
        {
            if (request == null)
                throw new ArgumentNullException(nameof(request), "Request cannot be null.");

            if (credential == null)
                throw new ArgumentNullException(nameof(credential), "Credential cannot be null.");

            // Existing logic for signing the request
            var timestamp = DateTime.UtcNow;
            var authData = GetAuthDataValue(credential, timestamp);
            var requestData = GetRequestData(request, uploadStream);
            var authorizationHeader = GetAuthorizationHeaderValue(credential, timestamp, authData, requestData);

            if (!request.Headers.Contains("Authorization"))
            {
                request.Headers.Add("Authorization", authorizationHeader);
            }
        }

        public async Task<HttpResponseMessage> ExecuteAsync(HttpRequestMessage request, ClientCredential credential, Stream uploadStream = null)
        {
            using (var client = new HttpClient())
            {
                Sign(request, credential, uploadStream);

                if (uploadStream != null && request.Method == HttpMethod.Post)
                {
                    request.Content = new StreamContent(uploadStream);
                    request.Content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/json");
                }

                return await client.SendAsync(request);
            }
        }
    }
}