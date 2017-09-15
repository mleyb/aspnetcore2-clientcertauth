using System;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace aspnetcore2_clientcertauth
{
    public class ClientCertificateAuthenticationOptions : AuthenticationSchemeOptions  
    {
        // Authentication options properties
    }

    public class ClientCertificateAuthenticationHandler : AuthenticationHandler<ClientCertificateAuthenticationOptions>  
    {
        public ClientCertificateAuthenticationHandler(IOptionsMonitor<ClientCertificateAuthenticationOptions> options, ILoggerFactory logger, UrlEncoder encoder, ISystemClock clock)
            : base(options, logger, encoder, clock) { }

        protected override Task<AuthenticateResult> HandleAuthenticateAsync()
        {
                return Task.FromResult(
                    AuthenticateResult.Success(
                        new AuthenticationTicket(
                            new ClaimsPrincipal(),
                            new AuthenticationProperties(),
                            this.Scheme.Name)));
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