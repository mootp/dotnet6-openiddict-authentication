
using Microsoft.AspNetCore.Identity;

namespace authServer.Entities;

public class ApplicationRole : IdentityRole<Guid>
{
    public string Description { get; set; }
    public ICollection<ApplicationUserRole> UserRoles { get; set; } = null!;
}