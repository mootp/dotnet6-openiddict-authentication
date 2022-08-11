using System.Security.Principal;
using authServer.Data;
using authServer.Entities;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.OpenApi.Models;
using OpenIddict.Abstractions;

var builder = WebApplication.CreateBuilder(args);

var services = builder.Services;
var config = builder.Configuration;

services.AddControllers();
services.AddControllersWithViews();
services.AddRazorPages();

services.AddSwaggerGen(c => c.SwaggerDoc("v1", new OpenApiInfo { Title = "auth server", Version = "v1" }));

services.AddDbContext<ApplicationDbContext>(options =>
{
    options.UseSqlServer(config.GetConnectionString("DefaultConnection"));
    options.UseOpenIddict();
});

services.Configure<IdentityOptions>(options =>
{
    options.ClaimsIdentity.UserNameClaimType = OpenIddictConstants.Claims.Username;
    options.ClaimsIdentity.UserIdClaimType = OpenIddictConstants.Claims.Subject;
    options.ClaimsIdentity.RoleClaimType = OpenIddictConstants.Claims.Role;
    // configure more options if necessary...
});

// OpenId Connect server configuration
services.AddOpenIddict()
.AddCore(options => options.UseEntityFrameworkCore().UseDbContext<ApplicationDbContext>())
.AddServer(options =>
{
    // Enable the required endpoints
    options.SetAuthorizationEndpointUris("/connect/authorize");
    options.SetLogoutEndpointUris("/connect/logout");
    options.SetTokenEndpointUris("/connect/token");
    options.SetIntrospectionEndpointUris("/introspect");
    options.SetUserinfoEndpointUris("/connect/userinfo");

    options.AllowAuthorizationCodeFlow();
    options.AllowPasswordFlow();
    options.AllowRefreshTokenFlow();
    // Add all auth flows that you want to support
    // Supported flows are:
    //      - Authorization code flow
    //      - Client credentials flow
    //      - Device code flow
    //      - Implicit flow
    //      - Password flow
    //      - Refresh token flow

    // Custom auth flows are also supported
    // options.AllowCustomFlow("custom_flow_name");

    // Force all client applications to use Proof Key for Code Exchange (PKCE).
    options.RequireProofKeyForCodeExchange();

    // Using reference tokens means that the actual access and refresh tokens are stored in the database
    // and a token referencing the actual tokens (in the db) is used in the request header.
    // The actual tokens are not made public.
    options.UseReferenceAccessTokens();
    options.UseReferenceRefreshTokens();

    // Disable Encryption token
    // options.DisableAccessTokenEncryption();

    // Register your scopes
    // Scopes are a list of identifiers used to specify what access privileges are requested.
    options.RegisterScopes(OpenIddictConstants.Permissions.Scopes.Email,
                                OpenIddictConstants.Permissions.Scopes.Profile,
                                OpenIddictConstants.Permissions.Scopes.Roles);

    // Set the lifetime of your tokens
    options.SetAccessTokenLifetime(TimeSpan.FromMinutes(30));
    options.SetRefreshTokenLifetime(TimeSpan.FromDays(7));

    // Register signing and encryption details
    // options.AddDevelopmentEncryptionCertificate()
    //         .AddDevelopmentSigningCertificate();
    options.AddEphemeralEncryptionKey()
            .AddEphemeralSigningKey();

    // Register ASP.NET Core host and configure options
    options.UseAspNetCore()
    .EnableStatusCodePagesIntegration()
    .EnableAuthorizationEndpointPassthrough()
    .EnableLogoutEndpointPassthrough()
    .EnableTokenEndpointPassthrough()
    .EnableUserinfoEndpointPassthrough();
})
.AddValidation(options =>
{
    options.UseLocalServer();
    options.UseAspNetCore();
    options.EnableAuthorizationEntryValidation();
});

// services.AddAuthentication(options =>
// {
//     options.DefaultScheme = OpenIddictConstants.Schemes.Bearer;
//     options.DefaultChallengeScheme = OpenIddictConstants.Schemes.Bearer;
// });

services.AddAuthentication(options =>
{
    options.DefaultScheme = OpenIddictConstants.Schemes.Bearer;
    options.DefaultChallengeScheme = OpenIddictConstants.Schemes.Bearer;
});

services.AddIdentity<ApplicationUser, ApplicationRole>(options => options.SignIn.RequireConfirmedAccount = false)
    .AddEntityFrameworkStores<ApplicationDbContext>()
    .AddSignInManager();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
    app.UseExceptionHandler("/Error");
    app.UseHsts();
    app.UseDeveloperExceptionPage();
}

app.UseHttpsRedirection();

app.UseStaticFiles();

app.UseRouting();

app.UseAuthentication();

app.UseAuthorization();

app.MapControllers();

app.MapRazorPages();

SeedData.Database(app);
SeedData.Clients(app);
SeedData.Scopes(app);
SeedData.Roles(app);
SeedData.Users(app);

app.Run();
