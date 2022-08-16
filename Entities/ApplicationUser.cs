using Microsoft.AspNetCore.Identity;

namespace authServer.Entities;

public class ApplicationUser : IdentityUser<Guid>
{
    public string FirstName { get; set; }
    public string LastName { get; set; }
    public ICollection<ApplicationUserRole> UserRoles { get; set; } = null!;
    public string DisplayName => $"{FirstName} {LastName}";
}