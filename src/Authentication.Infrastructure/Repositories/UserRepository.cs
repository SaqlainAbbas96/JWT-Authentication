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
            _db.users.Add(user);
            await _db.SaveChangesAsync();

            return "User registered successfully";
        }

        public async Task<string?> GetRole(int userId)
        {
            int roleId = _db.user_roles.Where(u => u.user_id == userId).Select(u => u.role_id).FirstOrDefault();
            string role = _db.roles.Where(r => r.id == roleId).Select(r => r.role_name).FirstOrDefault()!;
            return role;
        }

        public async Task<User?> CheckUser(string email)
        {
            var user = _db.users.FirstOrDefault(u => u.email == email);

            return user != null ? user : null;
        }
    }
}
