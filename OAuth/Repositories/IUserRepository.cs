using OAuth.Models;

namespace OAuth.Repositories
{
	public interface IUserRepository
	{
		Task<string> RegisterUser(User user);
		Task<User?> Checkuser(string email, string password);
		Task<string> GetRole(int userId);

		Task<string> Logout();
	}
}
