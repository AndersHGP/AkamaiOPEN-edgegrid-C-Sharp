using Akamai.EdgeGrid.Auth;
using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;

namespace Akamai.EdgeGrid
{
    class OpenAPI
    {
        static async Task Main(string[] args)
        {
            string secret = null;
            string clientToken = null;
            string accessToken = null;
            string apiurl = null;
            List<string> headers = new List<string>();
            string httpMethod = "GET";
            string contentType = "application/json";

            string outputfile = null;
            string uploadfile = null;
            string data = null;
            int maxBodySize = 2048;

            bool verbose = false;

            string firstarg = null;
            foreach (string arg in args)
            {
                if (firstarg != null)
                {
                    switch (firstarg)
                    {
                        case "-a":
                            accessToken = arg;
                            break;
                        case "-c":
                            clientToken = arg;
                            break;
                        case "-d":
                            if (httpMethod == "GET") httpMethod = "POST";
                            data = arg;
                            break;
                        case "-f":
                            if (httpMethod == "GET") httpMethod = "PUT";
                            uploadfile = arg;
                            break;
                        case "-H":
                            headers.Add(arg);
                            break;
                        case "-m":
                            maxBodySize = Convert.ToInt32(arg);
                            break;
                        case "-o":
                            outputfile = arg;
                            break;
                        case "-s":
                            secret = arg;
                            break;
                        case "-T":
                            contentType = arg;
                            break;
                        case "-X":
                            httpMethod = arg;
                            break;
                    }
                    firstarg = null;
                }
                else if (arg == "-h" || arg == "--help" || arg == "/?")
                {
                    help();
                    return;
                }
                else if (arg == "-v" || arg == "-vv")
                    verbose = true;
                else if (!arg.StartsWith("-"))
                    apiurl = arg;
                else
                    firstarg = arg;
            }

            if (verbose)
            {
                Console.WriteLine("{0} {1}", httpMethod, apiurl);
                Console.WriteLine("ClientToken: {0}", clientToken);
                Console.WriteLine("AccessToken: {0}", accessToken);
                Console.WriteLine("Secret: {0}", secret);
                if (data != null) Console.WriteLine("Data: [{0}]", data);
                if (uploadfile != null) Console.WriteLine("UploadFile: {0}", uploadfile);
                if (outputfile != null) Console.WriteLine("OutputFile: {0}", outputfile);
                foreach (string header in headers)
                    Console.WriteLine("{0}", header);
                Console.WriteLine("Content-Type: {0}", contentType);
            }

            await execute(httpMethod, apiurl, headers, clientToken, accessToken, secret, data, uploadfile, outputfile, maxBodySize, contentType, verbose);
        }

        static async Task execute(string httpMethod, string apiurl, List<string> headers, string clientToken, string accessToken, string secret, string data, string uploadfile, string outputfile, int? maxBodySize, string contentType, bool verbose = false)
        {
            if (apiurl == null || clientToken == null || accessToken == null || secret == null)
            {
                help();
                return;
            }

            EdgeGridV1Signer signer = new EdgeGridV1Signer(null, maxBodySize);
            ClientCredential credential = new ClientCredential(clientToken, accessToken, secret);

            Stream uploadStream = null;
            if (uploadfile != null)
                uploadStream = new FileInfo(uploadfile).OpenRead();
            else if (data != null)
                uploadStream = new MemoryStream(Encoding.UTF8.GetBytes(data.Trim('\''))); //TODO: remove this trim

            var request = new HttpRequestMessage(new HttpMethod(httpMethod), apiurl);

            foreach (string header in headers)
            {
                var headerParts = header.Split(new[] { ':' }, 2);
                if (headerParts.Length == 2)
                {
                    request.Headers.Add(headerParts[0].Trim(), headerParts[1].Trim());
                }
            }

            if (uploadStream != null)
            {
                request.Content = new StreamContent(uploadStream);
                request.Content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue(contentType);
            }

            if (verbose)
            {
                signer.Sign(request, credential, uploadStream);
                Console.WriteLine("Authorization: {0}", request.Headers.Authorization);
                Console.WriteLine();
            }

            using (var client = new HttpClient())
            {
                signer.Sign(request, credential, uploadStream);
                var response = await client.SendAsync(request);

                Stream output = Console.OpenStandardOutput();
                if (outputfile != null)
                    output = new FileInfo(outputfile).OpenWrite();

                using (output)
                {
                    var responseStream = await response.Content.ReadAsStreamAsync();
                    await responseStream.CopyToAsync(output);
                }
            }
        }

        static void help()
        {
            Console.Error.WriteLine(@"
Usage: openapi <-c client-token> <-a access-token> <-s secret>
           [-d data] [-f srcfile]
           [-o outfile]
           [-m max-size]
           [-X method]
           [-H header-line]
           [-T content-type]
           <url>

Where:
    -o outfile      local file name to use to save response from the API
    -d data         string of data to PUT to the API
    -f srcfile      local file used as source when action=upload
    -m max-size     maximum amount of data to use in the signing hash. Default is 2048
    -H header-line  Http Header 'Name: value'
    -X method       force HTTP PUT,POST,DELETE
    -T content-type the HTTP content type (default = application/json)
    url             fully qualified api url such as https://akab-1234.luna.akamaiapis.net/diagnostic-tools/v1/locations

");
        }
    }
}