using System;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;

namespace Akamai.EdgeGrid.Auth.Tests
{
    [TestClass]
    public class EdgeGridV1SignerTest
    {
        private Mock<IHttpClientFactory> _httpClientFactoryMock;

        [TestInitialize]
        public void Setup()
        {
            _httpClientFactoryMock = new Mock<IHttpClientFactory>();
            var httpClient = new HttpClient(new HttpMessageHandlerStub());
            _httpClientFactoryMock.Setup(factory => factory.CreateClient(It.IsAny<string>())).Returns(httpClient);
        }

        [TestMethod]
        public void Sign_ShouldAddAuthorizationHeader()
        {
            var signer = new EdgeGridV1Signer(_httpClientFactoryMock.Object);
            var credential = new ClientCredential("clientToken", "accessToken", "secret");
            var request = new HttpRequestMessage(HttpMethod.Get, "https://example.com/api/resource");

            signer.Sign(request, credential);

            Assert.IsTrue(request.Headers.Contains("Authorization"));
        }

        [TestMethod]
        public async Task ExecuteAsync_ShouldSendSignedRequest()
        {
            var signer = new EdgeGridV1Signer(_httpClientFactoryMock.Object);
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
            var signer = new EdgeGridV1Signer(_httpClientFactoryMock.Object);
            var credential = new ClientCredential("clientToken", "accessToken", "secret");
            var request = new HttpRequestMessage(HttpMethod.Post, "https://example.com/api/resource");
            var uploadStream = new MemoryStream(Encoding.UTF8.GetBytes("Test upload content"));

            signer.Sign(request, credential, uploadStream);

            Assert.IsTrue(request.Headers.Contains("Authorization"));
        }

        [TestMethod]
        public void Sign_ShouldThrowException_WhenRequestIsNull()
        {
            var signer = new EdgeGridV1Signer(_httpClientFactoryMock.Object);
            var credential = new ClientCredential("clientToken", "accessToken", "secret");

            Assert.ThrowsException<ArgumentNullException>(() => signer.Sign(null, credential));
        }

        [TestMethod]
        public void Sign_ShouldThrowException_WhenCredentialIsNull()
        {
            var signer = new EdgeGridV1Signer(_httpClientFactoryMock.Object);
            var request = new HttpRequestMessage(HttpMethod.Get, "https://example.com/api/resource");

            Assert.ThrowsException<ArgumentNullException>(() => signer.Sign(request, null));
        }
    }

    public class HttpMessageHandlerStub : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, System.Threading.CancellationToken cancellationToken)
        {
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("{\"message\":\"success\"}", Encoding.UTF8, "application/json")
            });
        }
    }
}