using Authentication.Domain.Entities;

namespace Authentication.Application.Interfaces
{
	public interface IUserRepository
	{
        Task RegisterUser(User user, string defaultRole);
        Task<User?> CheckUser(string email);
		Task<string?> GetRole(int userId);
        Task<bool> EmailExists(string email);
        Task CreateRefreshToken(RefreshToken refreshToken);
    }
}
