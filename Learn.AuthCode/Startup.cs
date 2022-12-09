using Learn.AuthCode.EF;
using Learn.AuthCode.OpenIddict;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Abstractions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace Learn.AuthCode;
public static class Startup
{
    public static void ConfigureDI(this WebApplicationBuilder builder)
    {
    }

    public static void ConfgureService(this WebApplicationBuilder builder)
    {
        builder.Services.AddControllers();
        builder.Services.AddDbContext<IdentityContext>(options =>
        {
            options.UseInMemoryDatabase("OAuthTest");
            options.UseOpenIddict();
        });

        builder.Services.AddDefaultIdentity<IdentityUser>(options =>
            {
                options.SignIn.RequireConfirmedAccount = false;
                options.Lockout.AllowedForNewUsers = false;

                // configure password security rules
                builder.Configuration.GetSection("OpenId:Password").Bind(options.Password);
            })
            .AddRoles<IdentityRole>()
            .AddRoleManager<RoleManager<IdentityRole>>()
            .AddEntityFrameworkStores<IdentityContext>()
            .AddDefaultTokenProviders();

        // Configure Identity to use the same JWT claims as OpenIddict instead
        // of the legacy WS-Federation claims it uses by default (ClaimTypes),
        // which saves you from doing the mapping in your authorization controller.
        builder.Services.Configure<IdentityOptions>(options =>
        {
            options.ClaimsIdentity.UserNameClaimType = OpenIddictConstants.Claims.Name;
            options.ClaimsIdentity.UserIdClaimType = OpenIddictConstants.Claims.Subject;
            options.ClaimsIdentity.RoleClaimType = OpenIddictConstants.Claims.Role;
            options.ClaimsIdentity.EmailClaimType = OpenIddictConstants.Claims.Email;
        });
    }

    /// <summary>
    /// Registers implementation of IOption&lt;OpenIddictConfiguration&gt; and IOpenIddictClientConfigurationProvider
    /// </summary>
    public static void AddOpenIddictConfiguration(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddTransient<IOpenIddictClientConfigurationProvider, OpenIddictClientConfigurationProvider>();
        services.Configure<OpenIddictConfiguration>(configuration);
    }

    public static void ConfigureAuth(this WebApplicationBuilder builder)
    {
        builder.Services.AddOpenIddict()
        .AddServer(options =>
        {
            var publicUrl = builder.Configuration.GetSection("Auth").
            GetValue<string>("PublicHost");

            var settings = new OpenIddictSettings(options);
            IConfiguration openIdConfiguration = builder.Configuration.GetSection("OpenId");

            settings.SetConfiguration(openIdConfiguration);
            settings.SetPublicUrl(publicUrl);

            options.Services.AddOpenIddictConfiguration(settings.Configuration);
            options.Services.AddTransient<ClientSeeder>();
            options.Services.AddSingleton<IPublicUrlProvider>(new PublicUrlProvider(settings.PublicUrl));

            options.AddDevelopmentEncryptionCertificate().AddDevelopmentSigningCertificate();

            options.SetTokenEndpointUris("/connect/token");
            options.UseAspNetCore().EnableTokenEndpointPassthrough();

            if (!settings.IsLogoutEndpointDisabled)
            {
                options.SetLogoutEndpointUris("/connect/logout");
                options.UseAspNetCore().EnableLogoutEndpointPassthrough();
            }

            if (!settings.IsAuthorizeFlowDisabled)
            {
                options
                    .AllowAuthorizationCodeFlow()
                    .RequireProofKeyForCodeExchange()
                    .SetAuthorizationEndpointUris("/connect/authorize");

                options.UseAspNetCore().EnableAuthorizationEndpointPassthrough();
            }

            if (settings.IsPasswordFlowAllowed)
            {
                options.AllowPasswordFlow();
            }

            if (!settings.IsRefreshTokenFlowDisabled)
            {
                options.AllowRefreshTokenFlow();
            }
        }).AddCore(options =>
        {
            options.UseEntityFrameworkCore().UseDbContext<IdentityContext>();
        });

        // var config = builder.Configuration.GetSection("Google").GetValue<string>("ClientId");

        builder.Services.AddAuthentication()
                .AddGoogle(options =>
                {

                    builder.Configuration.GetSection("Google").Bind(options);
                })
        .AddOpenIdConnect("Zoho", options =>
        {
            builder.Configuration.Bind("Zoho", options);
            options.ResponseType = OpenIdConnectResponseType.Code;
            options.ProtocolValidator.RequireNonce = false;
        });
    }

    /// <summary>
    /// Initializes OpenidDict clients according to configuration (usually from appsettings.json)
    /// </summary>
    private static async Task SeedOpenIdClientsAsync(this IServiceProvider applicationServices)
    {
        await using var scope = applicationServices.CreateAsyncScope();
        var serviceProvider = scope.ServiceProvider;

        var publicUrlProvider = serviceProvider.GetRequiredService<IPublicUrlProvider>();
        var clientSeeder = serviceProvider.GetRequiredService<ClientSeeder>();

        await clientSeeder.Seed(publicUrlProvider.PublicUrl);
    }

    public static void Configure(this WebApplication app)
    {
        var forwardedHeadersOptions = new ForwardedHeadersOptions
        {
            ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto
        };
        forwardedHeadersOptions.KnownNetworks.Clear();
        forwardedHeadersOptions.KnownProxies.Clear();
        app.UseForwardedHeaders(forwardedHeadersOptions);

        if (app.Environment.IsDevelopment())
        {
            app.UseDeveloperExceptionPage();
            app.UseHttpsRedirection();
        }
        else
        {
            // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
            app.UseHsts();
        }

        app.UseRouting();

        app.UseAuthentication();
        app.UseAuthorization();

        app.UseDefaultFiles();
        app.UseStaticFiles();
        app.MapControllers();

        Task.Run(app.Services.SeedOpenIdClientsAsync).GetAwaiter().GetResult();
    }
}
