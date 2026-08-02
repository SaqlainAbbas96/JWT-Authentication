using Authentication.Domain.Entities;

namespace Authentication.Application.Interfaces
{
	public interface IUserRepository
	{
		Task<string> RegisterUser(User user);
		Task<User?> Checkuser(string email, string password);
		Task<string> GetRole(int userId);
	}
}
