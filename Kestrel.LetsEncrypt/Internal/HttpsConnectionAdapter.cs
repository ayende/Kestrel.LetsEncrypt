// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.IO;
using System.Linq;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Kestrel.LetsEncrypt;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.Server.Kestrel.Core.Adapter.Internal;
using Microsoft.AspNetCore.Server.Kestrel.Core.Features;
using Microsoft.Extensions.Logging;

namespace Microsoft.AspNetCore.Server.Kestrel.Https.Internal
{
    public class HttpsConnectionAdapter : IConnectionAdapter
    {
        private readonly LetsEncryptCertificateFetcher _fetcher;

        // See http://oid-info.com/get/1.3.6.1.5.5.7.3.1
        // Indicates that a certificate can be used as a SSL server certificate
        private const string ServerAuthenticationOid = "1.3.6.1.5.5.7.3.1";

        private static readonly ClosedAdaptedConnection _closedAdaptedConnection = new ClosedAdaptedConnection();

        private readonly HttpsConnectionAdapterOptions _options;
        private readonly ILogger _logger;


        public HttpsConnectionAdapter(HttpsConnectionAdapterOptions options, ILoggerFactory loggerFactory, LetsEncryptCertificateFetcher fetcher)
        {
            _fetcher = fetcher;
            _options = options ?? throw new ArgumentNullException(nameof(options));
            _logger = loggerFactory?.CreateLogger(nameof(HttpsConnectionAdapter));
        }

        public bool IsHttps => true;

        public Task<IAdaptedConnection> OnConnectionAsync(ConnectionAdapterContext context)
        {
            // Don't trust SslStream not to block.
            return Task.Run(() => InnerOnConnectionAsync(context));
        }

        private async Task<IAdaptedConnection> InnerOnConnectionAsync(ConnectionAdapterContext context)
        {
            SslStream sslStream;
            bool certificateRequired;

            if (_options.ClientCertificateMode == ClientCertificateMode.NoCertificate)
            {
                sslStream = new SslStream(context.ConnectionStream);
                certificateRequired = false;
            }
            else
            {
                sslStream = new SslStream(context.ConnectionStream,
                    leaveInnerStreamOpen: false,
                    userCertificateValidationCallback: (sender, certificate, chain, sslPolicyErrors) =>
                    {
                        if (certificate == null)
                        {
                            return _options.ClientCertificateMode != ClientCertificateMode.RequireCertificate;
                        }

                        if (_options.ClientCertificateValidation == null)
                        {
                            if (sslPolicyErrors != SslPolicyErrors.None)
                            {
                                return false;
                            }
                        }

                        var certificate2 = ConvertToX509Certificate2(certificate);
                        if (certificate2 == null)
                        {
                            return false;
                        }

                        if (_options.ClientCertificateValidation != null)
                        {
                            if (!_options.ClientCertificateValidation(certificate2, chain, sslPolicyErrors))
                            {
                                return false;
                            }
                        }

                        return true;
                    });

                certificateRequired = true;
            }

            //TODO: removed this because this is not on Kestrel 2.0
            //var timeoutFeature = context.Features.Get<IConnectionTimeoutFeature>();
            //timeoutFeature.SetTimeout(_options.HandshakeTimeout);

            try
            {
                await sslStream.AuthenticateAsServerAsync(_fetcher.Certificate, certificateRequired,
                        _options.SslProtocols, _options.CheckCertificateRevocation);
            }
            catch (OperationCanceledException)
            {
                _logger?.LogInformation(2, HttpsStrings.AuthenticationTimedOut);
                sslStream.Dispose();
                return _closedAdaptedConnection;
            }
            catch (IOException ex)
            {
                _logger?.LogInformation(1, ex, HttpsStrings.AuthenticationFailed);
                sslStream.Dispose();
                return _closedAdaptedConnection;
            }
            finally
            {
                // TODO: restore this
                //timeoutFeature.CancelTimeout();
            }

            // Always set the feature even though the cert might be null
            context.Features.Set<ITlsConnectionFeature>(new TlsConnectionFeature
            {
                ClientCertificate = ConvertToX509Certificate2(sslStream.RemoteCertificate)
            });

            return new HttpsAdaptedConnection(sslStream);
        }

        private static X509Certificate2 ConvertToX509Certificate2(X509Certificate certificate)
        {
            if (certificate == null)
            {
                return null;
            }

            if (certificate is X509Certificate2 cert2)
            {
                return cert2;
            }

            return new X509Certificate2(certificate);
        }

        private class HttpsAdaptedConnection : IAdaptedConnection
        {
            private readonly SslStream _sslStream;

            public HttpsAdaptedConnection(SslStream sslStream)
            {
                _sslStream = sslStream;
            }

            public Stream ConnectionStream => _sslStream;

            public void Dispose()
            {
                _sslStream.Dispose();
            }
        }

        private class ClosedAdaptedConnection : IAdaptedConnection
        {
            public Stream ConnectionStream { get; } = new ClosedStream();

            public void Dispose()
            {
            }
        }
    }
}
