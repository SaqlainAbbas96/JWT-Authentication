using Authentication.Application.Interfaces;
using Authentication.Domain.Entities;
using Authentication.Infrastructure.Persistence;

namespace Authentication.Infrastructure.Repositories
{
    public class UserRepository : IUserRepository
    {
        private readonly DBContext _db;
        public UserRepository(DBContext db)
        {
            _db = db;
        }

        public async Task<string> RegisterUser(User user)
        {
            _db.Users.Add(user);
            await _db.SaveChangesAsync();

            return "User registered successfully";
        }

        public async Task<string?> GetRole(int userId)
        {
            int roleId = _db.UserRoles.Where(u => u.UserId == userId).Select(u => u.RoleId).FirstOrDefault();
            string role = _db.Roles.Where(r => r.Id == roleId).Select(r => r.RoleName).FirstOrDefault()!;
            return role;
        }

        public async Task<User?> Checkuser(string email, string password)
        {
            var user = _db.Users.FirstOrDefault(u => u.Email == email);

            return user != null ? user : null;
        }
    }
}
