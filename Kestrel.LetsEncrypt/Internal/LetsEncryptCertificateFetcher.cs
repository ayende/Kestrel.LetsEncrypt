using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Certes;
using Certes.Acme;
using Certes.Pkcs;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Microsoft.AspNetCore.Server.Kestrel.Https.Internal
{
    public class LetsEncryptCertificateFetcher : IDisposable
    {
        private X509Certificate2 _certificate;
        private Timer _timer;
        readonly string _domain;
        private readonly string _email;
        private readonly IPAddress _address;
        private readonly Func<string, byte[]> _tryGetCachedCertificate;
        private readonly Action<string, byte[]> _setCachedCertificate;

        private class LetEncryptHttpChallengerResponder: IStartup
        {
            public string ChallengeResponse { get; set; }

            public IServiceProvider ConfigureServices(IServiceCollection services)
            {
                return services.BuildServiceProvider();
            }

            public void Configure(IApplicationBuilder app)
            {
                app.Map("/.well-known/acme-challenge", sub =>
                {
                    sub.Run(async context =>
                    {
                        var path = context.Request.Path.ToUriComponent();
                        if (path != null && path.Length > 1 && path.StartsWith("/"))
                        {
                            context.Response.ContentType = "plain/text";
                            await context.Response.WriteAsync(ChallengeResponse);
                        }
                        else
                        {
                            context.Response.StatusCode = 404;
                        }
                    });
                });
            }
        }

        public LetsEncryptCertificateFetcher(string domain, string email, IPAddress address, 
            Func<string, byte[]> tryGetCachedCertificate, 
            Action<string, byte[]> setCachedCertificate)
        {
            _domain = domain;
            _email = email;
            _address = address;
            _tryGetCachedCertificate = tryGetCachedCertificate;
            _setCachedCertificate = setCachedCertificate;
        }

        public IPAddress Address => _address;
        public X509Certificate Certificate => _certificate;

        public async Task InitializeAsync()
        {
            var cachedCertificate = TryReadCachedCertificate();
            if (cachedCertificate != null && (DateTime.Today - cachedCertificate.NotAfter).TotalDays > 1)
            {
                _certificate = cachedCertificate;
                _timer = new Timer(Renew, null, TimeSpan.FromMinutes(1), Timeout.InfiniteTimeSpan);
                return;
            }
            await FetchCertificateFromLetsEncryptAsync();
        }

        private async Task FetchCertificateFromLetsEncryptAsync()
        {
            _timer = new Timer(Renew, null, TimeSpan.FromDays(1), Timeout.InfiniteTimeSpan);

            var challengerResponder = new LetEncryptHttpChallengerResponder();

            var host = new WebHostBuilder()
                .UseKestrel(options =>
                {
                    options.Listen(_address, 80);
                })
                .UseSetting(WebHostDefaults.ApplicationKey, GetType().FullName)
                .ConfigureServices(services =>
                {
                    services.AddSingleton(typeof(IStartup), 
                        challengerResponder);
                }).Build();

            var task = host.RunAsync();
            using (host)
            using (var client = new AcmeClient(WellKnownServers.LetsEncrypt))
            {
                // Create new registration
                var account = await client.NewRegistraton("mailto:" + _email);

                // Accept terms of services
                account.Data.Agreement = account.GetTermsOfServiceUri();
                await client.UpdateRegistration(account);

                // Initialize authorization
                var authz = await client.NewAuthorization(new AuthorizationIdentifier
                {
                    Type = AuthorizationIdentifierTypes.Dns,
                    Value = _domain
                });

                // Comptue key authorization for http-01
                var httpChallengeInfo = authz.Data.Challenges.First(c => c.Type == ChallengeTypes.Http01);
                var keyAuthString = client.ComputeKeyAuthorization(httpChallengeInfo);

                challengerResponder.ChallengeResponse = keyAuthString;


                var httpChallenge = await client.CompleteChallenge(httpChallengeInfo);

                // Check authorization status (use the proper challenge to check Authorization State)
                authz = await client.GetAuthorization(httpChallenge.Location); // or dnsChallenge.Location
                while (authz.Data.Status == EntityStatus.Pending)
                {
                    // Wait for ACME server to validate the identifier
                    await Task.Delay(250);
                    authz = await client.GetAuthorization(httpChallenge.Location);
                }

                if (authz.Data.Status != EntityStatus.Valid)
                    throw new InvalidOperationException("Failed to authorize certificate: " + authz.Data.Status);

                // Create certificate
                var csr = new CertificationRequestBuilder();
                csr.AddName("CN", _domain);
                var cert = await client.NewCertificate(csr);

                // Export Pfx
                var pfxBuilder = cert.ToPfx();
                var pfx = pfxBuilder.Build(_domain + " cert", "");
                _certificate = new X509Certificate2(pfx);

                _setCachedCertificate?.Invoke(_domain, pfx);

            }
            await task;

        }

        private X509Certificate2 TryReadCachedCertificate()
        {
            var cert = _tryGetCachedCertificate?.Invoke(_domain);
            return cert == null ? null : new X509Certificate2(cert);
        }

        private void Renew(object state)
        {
            var serverCertificate = _certificate;
            if (serverCertificate != null && (DateTime.Today - serverCertificate.NotAfter).TotalDays > 14)
                return;
            // ignoring exception, we'll retry anyway
            FetchCertificateFromLetsEncryptAsync().ContinueWith(t => GC.KeepAlive(t.Exception));
        }


        public void Dispose()
        {
            _certificate?.Dispose();
            _timer?.Dispose();
        }
    }
}