using Authentication.Application.Dtos;

namespace Authentication.Application.Interfaces
{
	public interface IUserService
	{
		Task<string> RegisterUser(UserDto userDto);
		Task<string> Authenticate(LoginDto user);
		void PasswordHash(string password, out byte[] passwordHash, out byte[] passwordSalt);
		bool VerifyHashPassword(string password, byte[] passwordHash, byte[] passwordSalt);
    }
}
