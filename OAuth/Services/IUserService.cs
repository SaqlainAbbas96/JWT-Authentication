using OAuth.Models;
using OAuth.Models.Dtos;
using System.Security.Cryptography;

namespace OAuth.Services
{
	public interface IUserService
	{
		Task<string> RegisterUser(UserDto userDto);
		Task<string> Authenticate(LoginDto user);
		void PasswordHash(string password, out byte[] passwordHash, out byte[] passwordSalt);
		Task<string> GetUserRole();
		bool VerifyHashPassword(string password, byte[] passwordHash, byte[] passwordSalt);
		Task<string> LogoutUser();

    }
}
