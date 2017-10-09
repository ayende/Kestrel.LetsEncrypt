using System;
using System.Net;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using Microsoft.AspNetCore.Server.Kestrel.Https.Internal;
using Microsoft.Extensions.Logging;

namespace Tryout
{
    class Program
    {
        static void Main(string[] args)
        {
            using (var fetcher = new LetsEncryptCertificateFetcher("ayende.hopto.org", "ayende@ayende.com", IPAddress.Any))
            {
                fetcher.InitializeAsync().Wait();

                var host = new WebHostBuilder()
                    .UseKestrel(options =>
                    {
                        options.UseLetsEncrypt(fetcher, new HttpsConnectionAdapterOptions());
                    })
                    .UseStartup<Startup>()
                    .Build();

                host.Run();
            }
        }

        public class Startup
        {
            public void Configure(IApplicationBuilder app, IHostingEnvironment env, ILoggerFactory loggerFactory)
            {
                app.Run(async context =>
                {
                    await context.Response.WriteAsync("Hello World via " + context.Request.Scheme);
                });
            }
        }
    }
}
