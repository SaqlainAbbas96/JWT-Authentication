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

        public async Task RegisterUser(
            User user, 
            string defaultRole,
            CancellationToken cancellationToken)
        {
            await using var transaction =
                await _db.Database.BeginTransactionAsync(
                    cancellationToken);

            try
            {
                _db.users.Add(user);

                await _db.SaveChangesAsync(
                    cancellationToken);

                var roleId = await _db.roles
                    .Where(r => r.role_name == defaultRole)
                    .Select(r => (int?)r.id)
                    .FirstOrDefaultAsync(
                        cancellationToken);

                if (roleId is null)
                {
                    throw new InvalidOperationException(
                        $"Role '{defaultRole}' does not exist.");
                }

                var userRole = new UserRoles
                {
                    user_id = user.id,
                    role_id = roleId.Value
                };

                _db.user_roles.Add(userRole);

                await _db.SaveChangesAsync(
                    cancellationToken);

                await transaction.CommitAsync(
                    cancellationToken);
            }
            catch (DbUpdateException ex) when (
                ex.InnerException is PostgresException postgresException &&
                postgresException.SqlState == PostgresErrorCodes.UniqueViolation)
            {
                await transaction.RollbackAsync(
                    CancellationToken.None);

                throw new ConflictException("Email is already registered.");
            }
            catch 
            {
                await transaction.RollbackAsync(
                    CancellationToken.None);

                throw;
            }
        }

        public async Task<string?> GetRole(
            int userId,
            CancellationToken cancellationToken)
        {
            return await _db.user_roles
                .Where(ur => ur.user_id == userId)
                .Join(
                    _db.roles,
                    ur => ur.role_id,
                    role => role.id,
                    (_, role) => role.role_name)
                .FirstOrDefaultAsync(
                    cancellationToken);
        }

        public async Task<User?> CheckUser(
            string email,
            CancellationToken cancellationToken)
        {
            return await _db.users
                .FirstOrDefaultAsync(
                    u => u.email == email,
                    cancellationToken);
        }

        public async Task<bool> EmailExists(
            string email,
            CancellationToken cancellationToken)
        {
            return await _db.users
                .AnyAsync(
                    u => u.email == email,
                    cancellationToken);
        }

        public async Task CreateRefreshToken(
            RefreshToken refreshToken,
            CancellationToken cancellationToken)
        {
            _db.refresh_tokens.Add(refreshToken);

            await _db.SaveChangesAsync(
                cancellationToken);
        }
    }
}
