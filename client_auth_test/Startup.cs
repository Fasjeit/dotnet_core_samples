using System;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Authentication.Certificate;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using System.Collections.Generic;

namespace client_auth_test
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            // adding certificate forwarding for proxy scenarios
            services.AddCertificateForwarding(options =>
            {
                options.CertificateHeader = "X-SSL-CERT";
                options.HeaderConverter = (headerValue) =>
                {
                    X509Certificate2 clientCertificate = null;

                    if (!string.IsNullOrWhiteSpace(headerValue))
                    {
                        byte[] bytes = HexHelper.StringToByteArray(headerValue);
                        clientCertificate = new X509Certificate2(bytes);
                    }

                    return clientCertificate;
                };
            });            

            services.AddControllers();

            //certificate autentication
            services.AddAuthentication(
                    CertificateAuthenticationDefaults.AuthenticationScheme)
                    .AddCertificate(options =>
                    {
                        options.AllowedCertificateTypes = CertificateTypes.All;
                        options.Events = new CertificateAuthenticationEvents
                        {
                            OnCertificateValidated = async context =>
                            {
                                var name = context.ClientCertificate.GetNameInfo(X509NameType.SimpleName, false);
                                var thumbprint = context.ClientCertificate.Thumbprint.ToLower();

                                var claimList = new List<Claim>();
                                claimList.Add(
                                    new Claim(
                                        ClaimTypes.NameIdentifier,
                                        context.ClientCertificate.Subject,
                                        ClaimValueTypes.String,
                                        context.ClientCertificate.Issuer));
                                claimList.Add(
                                    new Claim(
                                        ClaimTypes.Name,
                                        name,
                                        ClaimValueTypes.String,
                                        context.ClientCertificate.Issuer));
                                 claimList.Add(
                                    new Claim(
                                        ClaimTypes.Role,
                                        "Auth",
                                        ClaimValueTypes.String,
                                        context.ClientCertificate.Issuer));

                                if (claimList.Count != 0)
                                {
                                    context.Principal = new ClaimsPrincipal(new ClaimsIdentity(claimList, context.Scheme.Name));
                                    context.Success();
                                }
                            }
                        };
                    });

            services.AddAuthorization();
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }

            app.UseHttpsRedirection();

            app.UseRouting();

            // certificate forwarding before authentication and authorization
            app.UseCertificateForwarding();

            app.UseAuthentication();
            app.UseAuthorization();           

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllers();
            });
        }
    }
    public class HexHelper
    {
        public static byte[] StringToByteArray(string hex)
        {
            int NumberChars = hex.Length;
            byte[] bytes = new byte[NumberChars / 2];

            for (int i = 0; i < NumberChars; i += 2)
            {
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            }

            return bytes;
        }
    }
}
