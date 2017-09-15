using System;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace aspnetcore2_clientcertauth
{
    public class ClientCertificateAuthenticationOptions : AuthenticationSchemeOptions  
    {
        public string Thumbprint { get; set; }
    }

    public class ClientCertificateAuthenticationHandler : AuthenticationHandler<ClientCertificateAuthenticationOptions>  
    {
        public ClientCertificateAuthenticationHandler(IOptionsMonitor<ClientCertificateAuthenticationOptions> options, ILoggerFactory logger, UrlEncoder encoder, ISystemClock clock)
            : base(options, logger, encoder, clock) { }

        protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
        {base.
            X509Certificate2 cert = await Context.Connection.GetClientCertificateAsync();

            if (cert != null && cert.Thumbprint == Options.Thumbprint)
            {
                var ticket = new AuthenticationTicket(
                    new ClaimsPrincipal(),
                    new AuthenticationProperties(),
                    Scheme.Name);

                return AuthenticateResult.Success(ticket);
            }
            else
            {
                return AuthenticateResult.Fail("Client certificate required");
            }
        }
    }

    public static class CustomAuthenticationExtensions  
    {
        public static AuthenticationBuilder AddClientCertificateAuthentication(this AuthenticationBuilder builder, Action<ClientCertificateAuthenticationOptions> configureOptions)
        {
            return builder.AddScheme<ClientCertificateAuthenticationOptions, ClientCertificateAuthenticationHandler>("Client Certificate", "Client Certificate", configureOptions);
        }
    }
}