using System.Security.Cryptography;
using OpenIddict.Abstractions;

namespace authServer.Helpers
{
    public static class Utility
    {
        public static string GenerateClientSecret()
        {
            var bytes = new byte[32];
            using var rand = RandomNumberGenerator.Create();
            rand.GetBytes(bytes);
            return Convert.ToBase64String(bytes);
        }

        public static List<string> GetAllowedScopes(OpenIddictApplicationDescriptor descriptor)
        {
            var scopes = new List<string>();
            foreach (string permission in descriptor.Permissions)
            {
                if (permission.StartsWith(OpenIddictConstants.Permissions.Prefixes.Scope))
                    scopes.Add(permission);
            }

            return scopes;
        }

        public static List<string> GetAllowedPermissions(OpenIddictApplicationDescriptor descriptor)
        {
            var list = new List<string>();
            foreach (string permission in descriptor.Permissions)
            {
                if (!permission.StartsWith(OpenIddictConstants.Permissions.Prefixes.Scope))
                    list.Add(permission);
            }

            return list;
        }

        public static List<string> GetAllScopes()
        {
            var list = new List<string>();

            list.Add(OpenIddictConstants.Permissions.Scopes.Address);
            list.Add(OpenIddictConstants.Permissions.Scopes.Email);
            list.Add(OpenIddictConstants.Permissions.Scopes.Phone);
            list.Add(OpenIddictConstants.Permissions.Scopes.Profile);
            list.Add(OpenIddictConstants.Permissions.Scopes.Roles);

            return list;
        }

        public static List<string> GetAllPermissions()
        {
            var list = new List<string>();

            list.Add(OpenIddictConstants.Permissions.Endpoints.Authorization);
            list.Add(OpenIddictConstants.Permissions.Endpoints.Device);
            list.Add(OpenIddictConstants.Permissions.Endpoints.Introspection);
            list.Add(OpenIddictConstants.Permissions.Endpoints.Logout);
            list.Add(OpenIddictConstants.Permissions.Endpoints.Revocation);
            list.Add(OpenIddictConstants.Permissions.Endpoints.Token);

            list.Add(OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode);
            list.Add(OpenIddictConstants.Permissions.GrantTypes.ClientCredentials);
            list.Add(OpenIddictConstants.Permissions.GrantTypes.DeviceCode);
            list.Add(OpenIddictConstants.Permissions.GrantTypes.Implicit);
            list.Add(OpenIddictConstants.Permissions.GrantTypes.Password);
            list.Add(OpenIddictConstants.Permissions.GrantTypes.RefreshToken);

            // list.Add(OpenIddictConstants.Permissions.Prefixes.Endpoint);
            // list.Add(OpenIddictConstants.Permissions.Prefixes.GrantType);
            // list.Add(OpenIddictConstants.Permissions.Prefixes.ResponseType);
            // list.Add(OpenIddictConstants.Permissions.Prefixes.Scope);

            list.Add(OpenIddictConstants.Permissions.ResponseTypes.Code);
            list.Add(OpenIddictConstants.Permissions.ResponseTypes.CodeIdToken);
            list.Add(OpenIddictConstants.Permissions.ResponseTypes.CodeIdTokenToken);
            list.Add(OpenIddictConstants.Permissions.ResponseTypes.CodeToken);
            list.Add(OpenIddictConstants.Permissions.ResponseTypes.IdToken);
            list.Add(OpenIddictConstants.Permissions.ResponseTypes.IdTokenToken);
            list.Add(OpenIddictConstants.Permissions.ResponseTypes.None);
            list.Add(OpenIddictConstants.Permissions.ResponseTypes.Token);

            // list.Add(OpenIddictConstants.Permissions.Scopes.Address);
            // list.Add(OpenIddictConstants.Permissions.Scopes.Email);
            // list.Add(OpenIddictConstants.Permissions.Scopes.Phone);
            // list.Add(OpenIddictConstants.Permissions.Scopes.Profile);
            // list.Add(OpenIddictConstants.Permissions.Scopes.Roles);

            return list;
        }
    }
}
