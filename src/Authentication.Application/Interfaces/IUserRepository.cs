using Authentication.Domain.Entities;

namespace Authentication.Application.Interfaces
{
	public interface IUserRepository
	{
		Task<string> RegisterUser(User user);
		Task<User?> CheckUser(string email);
		Task<string> GetRole(int userId);
	}
}
