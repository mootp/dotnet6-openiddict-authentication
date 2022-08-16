namespace authServer.Data;
public static class ApplicationConstants
{
    public const string RoleSystem = "system";
    public const string RoleAdmin = "admin";
    public const string RoleManager = "manager";
    public const string RoleLeader = "leader";
    public const string RoleStaff = "staff";

    public static readonly Dictionary<string, string[]> StandardScopes = new()
        {
            // {"email", new string[]{"email", "email_verified" } },
            // {"address", new string[]{ "address" } },
            // {"profile", new string[]{ "name", "family_name", "given_name", "middle_name", "nickname",
            //     "preferred_username", "profile", "picture", "website", "gender", "birthdate",
            //     "zoneinfo", "locale", "updated_at" } },
            // {"phone", new string[]{"phone_number", "phone_number_verified"} }
        };

    public static class Policy
    {
        public const string IsSystem = "IsSystem";
    }
}