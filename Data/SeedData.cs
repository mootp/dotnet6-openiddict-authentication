using authServer.Entities;
using Microsoft.AspNetCore.Identity;
using OpenIddict.Abstractions;

namespace authServer.Data;

public static class SeedData
{
    public static async void Database(IApplicationBuilder app)
    {
        using var scope = app.ApplicationServices.GetRequiredService<IServiceScopeFactory>().CreateScope();
        var context = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
        await context.Database.EnsureCreatedAsync();
    }
    public static async void Clients(IApplicationBuilder app)
    {
        var listApp = new List<OpenIddictApplicationDescriptor>();

        listApp.Add(new OpenIddictApplicationDescriptor
        {
            ClientId = "client_app",
            ClientSecret = "050fdac1-21c8-455e-adef-ff81c4364269",
            DisplayName = "client application",
            ConsentType = OpenIddictConstants.ConsentTypes.Explicit,
            RedirectUris =
            {
                new Uri("https://oauth.pstmn.io/v1/callback"),
                new Uri("https://localhost:3000/callback"),
                new Uri("https://localhost:4200/callback")
            },
            Permissions =
            {
                OpenIddictConstants.Permissions.Endpoints.Authorization,
                OpenIddictConstants.Permissions.Endpoints.Logout,
                OpenIddictConstants.Permissions.Endpoints.Token,

                OpenIddictConstants.Permissions.GrantTypes.Password,
                OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode,
                OpenIddictConstants.Permissions.GrantTypes.ClientCredentials,
                OpenIddictConstants.Permissions.GrantTypes.RefreshToken,

                OpenIddictConstants.Permissions.ResponseTypes.Code,

                OpenIddictConstants.Permissions.Scopes.Email,
                OpenIddictConstants.Permissions.Scopes.Profile,
                OpenIddictConstants.Permissions.Scopes.Roles,

                OpenIddictConstants.Permissions.Prefixes.Scope + "api1",
                OpenIddictConstants.Permissions.Prefixes.Scope + "api2"
            },
            Requirements =
            {
                OpenIddictConstants.Requirements.Features.ProofKeyForCodeExchange
            }
        });

        listApp.Add(new OpenIddictApplicationDescriptor
        {
            ClientId = "resource_server_1",
            ClientSecret = "9405b8c4-58db-4b88-b9aa-7e93ff24ba74",
            DisplayName = "resource server 1",
            Permissions =
            {
                OpenIddictConstants.Permissions.Endpoints.Introspection
            }
        });

        listApp.Add(new OpenIddictApplicationDescriptor
        {
            ClientId = "resource_server_2",
            ClientSecret = "493c901b-41fb-4fa6-9978-2a20922be43a",
            DisplayName = "resource server 2",
            Permissions =
            {
                OpenIddictConstants.Permissions.Endpoints.Introspection
            }
        });

        using var scope = app.ApplicationServices.GetRequiredService<IServiceScopeFactory>().CreateScope();
        var appManager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();

        foreach (var item in listApp)
        {
            var existing = await appManager.FindByClientIdAsync(item.ClientId!);
            if (existing == null)
            {
                await appManager.CreateAsync(item);
            }
        }
    }

    public static async void Scopes(IApplicationBuilder app)
    {
        var listScope = new List<OpenIddictScopeDescriptor>();
        listScope.Add(new OpenIddictScopeDescriptor { Name = "api1", Resources = { "resource_server_1" } });
        listScope.Add(new OpenIddictScopeDescriptor { Name = "api2", Resources = { "resource_server_2" } });

        using var scope = app.ApplicationServices.GetRequiredService<IServiceScopeFactory>().CreateScope();
        var scopeManager = scope.ServiceProvider.GetRequiredService<IOpenIddictScopeManager>();
        foreach (var item in listScope)
        {
            var existing = await scopeManager.FindByNameAsync(item.Name!);
            if (existing == null)
            {
                await scopeManager.CreateAsync(item);
            }
        }
    }

    public static async void Roles(IApplicationBuilder app)
    {
        var listScope = new List<ApplicationRole>();
        listScope.Add(new ApplicationRole { Name = ApplicationConstants.RoleSystem });
        listScope.Add(new ApplicationRole { Name = ApplicationConstants.RoleAdmin });
        listScope.Add(new ApplicationRole { Name = ApplicationConstants.RoleManager });
        listScope.Add(new ApplicationRole { Name = ApplicationConstants.RoleLeader });
        listScope.Add(new ApplicationRole { Name = ApplicationConstants.RoleStaff });

        using var scope = app.ApplicationServices.GetRequiredService<IServiceScopeFactory>().CreateScope();
        var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<ApplicationRole>>();
        foreach (var item in listScope)
        {
            var existing = await roleManager.FindByNameAsync(item.Name);
            if (existing == null)
            {
                await roleManager.CreateAsync(item);
            }
        }
    }
    public static async void Users(IApplicationBuilder app)
    {
        var listUser = new List<ApplicationUser>();
        listUser.Add(new ApplicationUser { UserName = "sysadmin", FirstName = "System", LastName = "Admin" });

        using var scope = app.ApplicationServices.GetRequiredService<IServiceScopeFactory>().CreateScope();

        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        foreach (var item in listUser)
        {
            var existing = userManager.FindByNameAsync(item.UserName).GetAwaiter().GetResult();
            if (existing == null)
            {
                await userManager.CreateAsync(item, "P@ssw0rdSys");
                await userManager.AddToRoleAsync(item, ApplicationConstants.RoleSystem);
            }
        }

    }
}