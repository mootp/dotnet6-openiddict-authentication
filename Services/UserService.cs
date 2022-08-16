using authServer.Data;
using authServer.Entities;
using Microsoft.EntityFrameworkCore;

namespace authServer.Services
{
    public class UserService
    {
        private readonly ApplicationDbContext _db;

        public UserService(ApplicationDbContext db)
        {
            _db = db;
        }

        public List<ApplicationUser> GetUsers()
        {
            return _db.Users.Include(o => o.UserRoles).ThenInclude(o => o.Role).OrderBy(u => u.FirstName).ThenBy(u => u.LastName).ToList();
        }

        public ApplicationUser GetUser(Guid id)
        {
            return _db.Users.Include(o => o.UserRoles).ThenInclude(o => o.Role).FirstOrDefault(x => x.Id == id);
        }

        public void SaveChanges() => _db.SaveChanges();
    }
}
