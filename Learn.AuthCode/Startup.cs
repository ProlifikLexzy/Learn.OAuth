using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Learn.AuthCode;
public static class Startup
{
    public static void ConfigureAuth(this WebApplicationBuilder builder)
    {
        builder.Services
            .AddOpenIddict()
            .AddServer(options =>
            {
                options.AddDevelopmentEncryptionCertificate()
                                   .AddDevelopmentSigningCertificate();

                options.SetTokenEndpointUris("/connect/token");
                options.UseAspNetCore().EnableTokenEndpointPassthrough();


                options.SetLogoutEndpointUris("/connect/logout");
                options.UseAspNetCore().EnableLogoutEndpointPassthrough();

                options
                    .AllowAuthorizationCodeFlow()
                    .RequireProofKeyForCodeExchange()
                    .SetAuthorizationEndpointUris("/connect/authorize");

                options.UseAspNetCore().EnableAuthorizationEndpointPassthrough();


                options.AllowPasswordFlow();

                options.AllowRefreshTokenFlow();
            });

    }

     /// <summary>
    /// Initializes OpenidDict clients according to configuration (usually from appsettings.json)
    /// </summary>
    public static async Task SeedOpenIdClientsAsync(this IServiceProvider applicationServices)
    {
        await using var scope = applicationServices.CreateAsyncScope();
        var serviceProvider = scope.ServiceProvider;

        var publicUrlProvider = serviceProvider.GetRequiredService<IPublicUrlProvider>();
        var clientSeeder = serviceProvider.GetRequiredService<ClientSeeder>();

        await clientSeeder.Seed(publicUrlProvider.PublicUrl);
    }
}
