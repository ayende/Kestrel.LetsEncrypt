// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.IO;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using Microsoft.AspNetCore.Server.Kestrel.Https.Internal;
using Microsoft.AspNetCore.Server.Kestrel.Transport.Abstractions.Internal;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Microsoft.AspNetCore.Hosting
{
    public static class ListenOptionsHttpsExtensions
    {
        public static KestrelServerOptions UseLetsEncrypt(this KestrelServerOptions options,
            LetsEncryptCertificateFetcher fetcher, HttpsConnectionAdapterOptions httpsOptions = null, int port = 443)
        {
            if (port == 80)
                throw new ArgumentOutOfRangeException(nameof(port), "The value 80 is reserved for Let's Encrypt checks");

            options.Listen(fetcher.Address, port, listenOptions =>
            {
                var loggerFactory = listenOptions.KestrelServerOptions.ApplicationServices
                    .GetRequiredService<ILoggerFactory>();
                listenOptions.ConnectionAdapters.Add(
                    new HttpsConnectionAdapter(httpsOptions ?? new HttpsConnectionAdapterOptions(), 
                    loggerFactory,
                    fetcher));
            });
           
            return options;
        }
    }
}
