using Authentication.Domain.Entities;

namespace Authentication.Application.Interfaces
{
	public interface IUserRepository
	{
        Task RegisterUser(
            User user, 
            string defaultRole,
            CancellationToken cancellationToken);

        Task<User?> CheckUser(
            string email,
            CancellationToken cancellationToken);

		Task<string?> GetRole(
            int userId, 
            CancellationToken cancellationToken);

        Task<bool> EmailExists(
            string email,
            CancellationToken cancellationToken);

        Task CreateRefreshToken(
            RefreshToken refreshToken,
            CancellationToken cancellationToken);
    }
}
