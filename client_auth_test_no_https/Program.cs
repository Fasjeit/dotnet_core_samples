using System;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using Microsoft.Extensions.Hosting;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Server.Kestrel.Core;

namespace client_auth_test
{
    public class Program
    {
        public static void Main(string[] args)
        {
            CreateHostBuilder(args).Build().Run();
        }

        public static IHostBuilder CreateHostBuilder(string[] args) =>
            Host.CreateDefaultBuilder(args)
                .ConfigureWebHostDefaults(webBuilder =>
                {
                    webBuilder.UseStartup<Startup>();
                    webBuilder.ConfigureKestrel(
                        (context, options) =>
                        {
                            options.Listen(IPAddress.Any, 5000, listenOptions =>
                            {
#if DISABLE_HTTPS
#else
                                listenOptions.UseHttps((httpsOptions) =>
                                {                  
                                    using (var store = new X509Store(StoreName.My, StoreLocation.CurrentUser))
                                    {              
                                        // this is what will make the browser display the client certificate dialog
                                        httpsOptions.ClientCertificateMode = ClientCertificateMode.AllowCertificate;
                                        httpsOptions.CheckCertificateRevocation = false;
                                        httpsOptions.ClientCertificateValidation = (certificate2, validationChain, policyErrors) =>
                                        {
                                            return true;

                                        //// this is for testing non production certificates, do not use these settings in production
                                        //validationChain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                                        //validationChain.ChainPolicy.RevocationFlag = X509RevocationFlag.ExcludeRoot;
                                        //validationChain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority;
                                        //validationChain.ChainPolicy.VerificationTime = DateTime.Now;
                                        //validationChain.ChainPolicy.UrlRetrievalTimeout = new TimeSpan(0, 0, 0);
                                        //validationChain.ChainPolicy.ExtraStore.Add(serverCert);

                                        //var valid = validationChain.Build(certificate2);
                                        //if (!valid)
                                        //    return false;

                                        //    // only trust certs that are signed by our CA cert
                                        //    valid = validationChain.ChainElements
                                        //            .Cast<X509ChainElement>()
                                        //            .Any(x => x.Certificate.Thumbprint == serverCert.Thumbprint);

                                        //return valid;
                                        };                
                                    }                    
                                });
#endif
                            }
                            );
                        }
                    );
                });
    }
}
