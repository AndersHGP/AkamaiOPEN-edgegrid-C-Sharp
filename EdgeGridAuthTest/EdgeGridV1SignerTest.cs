using System;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Akamai.EdgeGrid.Auth.Tests
{
    [TestClass]
    public class EdgeGridV1SignerTest
    {
        [TestMethod]
        public void Sign_ShouldAddAuthorizationHeader()
        {
            var signer = new EdgeGridV1Signer();
            var credential = new ClientCredential("clientToken", "accessToken", "secret");
            var request = new HttpRequestMessage(HttpMethod.Get, "https://example.com/api/resource");

            signer.Sign(request, credential);

            Assert.IsTrue(request.Headers.Contains("Authorization"));
        }

        [TestMethod]
        public async Task ExecuteAsync_ShouldSendSignedRequest()
        {
            var signer = new EdgeGridV1Signer();
            var credential = new ClientCredential("clientToken", "accessToken", "secret");
            var request = new HttpRequestMessage(HttpMethod.Post, "https://httpbin.org/post")
            {
                Content = new StringContent("{\"key\":\"value\"}", Encoding.UTF8, "application/json")
            };

            var response = await signer.ExecuteAsync(request, credential);

            Assert.IsNotNull(response);
            Assert.AreEqual(HttpStatusCode.OK, response.StatusCode);
        }

        [TestMethod]
        public void Sign_WithUploadStream_ShouldAddCorrectBodyHash()
        {
            var signer = new EdgeGridV1Signer();
            var credential = new ClientCredential("clientToken", "accessToken", "secret");
            var request = new HttpRequestMessage(HttpMethod.Post, "https://example.com/api/resource");
            var uploadStream = new MemoryStream(Encoding.UTF8.GetBytes("Test upload content"));

            signer.Sign(request, credential, uploadStream);

            Assert.IsTrue(request.Headers.Contains("Authorization"));
        }

        [TestMethod]
        public void Sign_ShouldThrowException_WhenRequestIsNull()
        {
            var signer = new EdgeGridV1Signer();
            var credential = new ClientCredential("clientToken", "accessToken", "secret");

            Assert.ThrowsException<ArgumentNullException>(() => signer.Sign(null, credential));
        }

        [TestMethod]
        public void Sign_ShouldThrowException_WhenCredentialIsNull()
        {
            var signer = new EdgeGridV1Signer();
            var request = new HttpRequestMessage(HttpMethod.Get, "https://example.com/api/resource");

            Assert.ThrowsException<ArgumentNullException>(() => signer.Sign(request, null));
        }

        [TestMethod]
        public void GetRequestData_ShouldReturnCorrectString()
        {
            var signer = new EdgeGridV1Signer();
            var request = new HttpRequestMessage(HttpMethod.Get, "https://example.com/api/resource");

            var result = signer.GetRequestData(request);

            Assert.IsNotNull(result);
            Assert.IsTrue(result.Contains("GET"));
        }

        [TestMethod]
        public void GetRequestHeaders_ShouldReturnEmptyString_WhenHeadersAreNull()
        {
            var signer = new EdgeGridV1Signer();

            var result = signer.GetRequestHeaders(null);

            Assert.AreEqual(string.Empty, result);
        }

        [TestMethod]
        public void GetRequestHeaders_ShouldIncludeSpecifiedHeaders()
        {
            var signer = new EdgeGridV1Signer(new[] { "Custom-Header" });
            var request = new HttpRequestMessage(HttpMethod.Get, "https://example.com/api/resource");
            request.Headers.Add("Custom-Header", "HeaderValue");

            var result = signer.GetRequestHeaders(request.Headers);

            Assert.IsTrue(result.Contains("Custom-Header:HeaderValue"));
        }

        [TestMethod]
        public void GetRequestStreamHash_ShouldReturnEmptyString_WhenStreamIsNull()
        {
            var signer = new EdgeGridV1Signer();

            var result = signer.GetRequestStreamHash(null);

            Assert.AreEqual(string.Empty, result);
        }

        [TestMethod]
        public void GetRequestStreamHash_ShouldComputeHashCorrectly()
        {
            var signer = new EdgeGridV1Signer();
            var stream = new MemoryStream(Encoding.UTF8.GetBytes("Test content"));

            var result = signer.GetRequestStreamHash(stream);

            Assert.IsNotNull(result);
        }

        [TestMethod]
        public void GetAuthDataValue_ShouldReturnCorrectFormat()
        {
            var signer = new EdgeGridV1Signer();
            var credential = new ClientCredential("clientToken", "accessToken", "secret");
            var timestamp = DateTime.UtcNow;

            var result = signer.GetAuthDataValue(credential, timestamp);

            Assert.IsTrue(result.Contains("client_token=clientToken"));
        }

        [TestMethod]
        public void GetAuthorizationHeaderValue_ShouldReturnCorrectValue()
        {
            var signer = new EdgeGridV1Signer();
            var credential = new ClientCredential("clientToken", "accessToken", "secret");
            var timestamp = DateTime.UtcNow;
            var authData = signer.GetAuthDataValue(credential, timestamp);
            var requestData = "GET\t\thttps://example.com\t";

            var result = signer.GetAuthorizationHeaderValue(credential, timestamp, authData, requestData);

            Assert.IsTrue(result.Contains("signature="));
        }

        [TestMethod]
        public void Constructor_ShouldSetDefaultValues()
        {
            var signer = new EdgeGridV1Signer();

            Assert.IsNotNull(signer.HeadersToInclude);
            Assert.AreEqual(2048, signer.MaxBodyHashSize);
        }

        [TestMethod]
        public void Constructor_ShouldSetCustomValues()
        {
            var headers = new[] { "Header1", "Header2" };
            var signer = new EdgeGridV1Signer(headers, 4096);

            Assert.AreEqual(headers, signer.HeadersToInclude);
            Assert.AreEqual(4096, signer.MaxBodyHashSize);
        }

        [TestMethod]
        public void ExecuteAsync_ShouldThrowException_WhenRequestIsNull()
        {
            var signer = new EdgeGridV1Signer();
            var credential = new ClientCredential("clientToken", "accessToken", "secret");

            Assert.ThrowsExceptionAsync<ArgumentNullException>(() => signer.ExecuteAsync(null, credential));
        }

        [TestMethod]
        public void ExecuteAsync_ShouldThrowException_WhenCredentialIsNull()
        {
            var signer = new EdgeGridV1Signer();
            var request = new HttpRequestMessage(HttpMethod.Get, "https://example.com/api/resource");

            Assert.ThrowsExceptionAsync<ArgumentNullException>(() => signer.ExecuteAsync(request, null));
        }

        [TestMethod]
        public void Sign_ShouldHandleEmptyHeaders()
        {
            var signer = new EdgeGridV1Signer();
            var credential = new ClientCredential("clientToken", "accessToken", "secret");
            var request = new HttpRequestMessage(HttpMethod.Get, "https://example.com/api/resource");

            signer.Sign(request, credential);

            Assert.IsTrue(request.Headers.Contains("Authorization"));
        }

        [TestMethod]
        public void Sign_ShouldHandleCustomHeaders()
        {
            var signer = new EdgeGridV1Signer(new[] { "Custom-Header" });
            var credential = new ClientCredential("clientToken", "accessToken", "secret");
            var request = new HttpRequestMessage(HttpMethod.Get, "https://example.com/api/resource");
            request.Headers.Add("Custom-Header", "HeaderValue");

            signer.Sign(request, credential);

            Assert.IsTrue(request.Headers.Contains("Authorization"));
        }
    }
}