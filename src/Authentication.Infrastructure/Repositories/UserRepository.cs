using Authentication.Application.Exceptions;
using Authentication.Application.Interfaces;
using Authentication.Domain.Entities;
using Authentication.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Npgsql;

namespace Authentication.Infrastructure.Repositories
{
    public class UserRepository : IUserRepository
    {
        private readonly DBContext _db;
        public UserRepository(DBContext db)
        {
            _db = db;
        }

        public async Task RegisterUser(User user)
        {
            _db.users.Add(user);

            try
            {
                await _db.SaveChangesAsync();
            }
            catch (DbUpdateException ex) when (
                ex.InnerException is PostgresException postgresException &&
                postgresException.SqlState == PostgresErrorCodes.UniqueViolation)
            {
                throw new ConflictException("Email is already registered.");
            }
        }

        public async Task<string?> GetRole(int userId)
        {
            return await _db.user_roles
                .Where(ur => ur.user_id == userId)
                .Join(
                    _db.roles,
                    ur => ur.role_id,
                    role => role.id,
                    (_, role) => role.role_name)
                .FirstOrDefaultAsync();
        }

        public async Task<User?> CheckUser(string email)
        {
            return await _db.users.FirstOrDefaultAsync(u => u.email == email);
        }

        public async Task<bool> EmailExists(string email)
        {
            return await _db.users.AnyAsync(u => u.email == email);
        }
    }
}
