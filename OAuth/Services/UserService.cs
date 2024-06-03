using Microsoft.IdentityModel.Tokens;
using OAuth.Models;
using OAuth.Models.Dtos;
using OAuth.Repositories;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;

namespace OAuth.Services
{
	public class UserService : IUserService
	{
		private readonly IUserRepository _userRepository;
		private readonly IJwtAuthenticationService _jwtAuthenticationService;
		public UserService(IUserRepository userRepository, IJwtAuthenticationService jwtAuthenticationService)
        	{
			_jwtAuthenticationService = jwtAuthenticationService;
			_userRepository = userRepository;
        	}

	        public async Task<string> RegisterUser(UserDto userDto)
		{
			if (string.IsNullOrEmpty(userDto.email))
				return "Please provide your email";

			User user = new User();

			PasswordHash(userDto.password, out byte[] passwordHash, out byte[] passwordSalt);

			user.email = userDto.email;
			user.passwordHash = passwordHash;
			user.passwordSalt = passwordSalt;

			var res = await _userRepository.RegisterUser(user);
			return res;
		}

		public async Task<string> Authenticate(LoginDto loginDto)
		{
			var user = await _userRepository.Checkuser(loginDto.email, loginDto.password);

			if (user is not null) 
			{
				Global.userId = user.id;
				var userRole = await _userRepository.GetRole(user.id);

				bool isPasswordCorrect = VerifyHashPassword(loginDto.password, user.passwordHash, user.passwordSalt);
				return isPasswordCorrect ? _jwtAuthenticationService.GenerateToken(loginDto.email, userRole) : "Invalid Password";
			}
			else
				return "Invalid Credentials";
		}

		public void PasswordHash(string password, out byte[] passwordHash, out byte[] passwordSalt)
		{
			using (var h = new HMACSHA512())
			{
				passwordSalt = h.Key;
				passwordHash = h.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
			}
		}

		public async Task<string> GetUserRole()
		{
			var userrole = await _userRepository.GetRole(Global.userId);
			return userrole;
		}

		public bool VerifyHashPassword(string password, byte[] passwordHash, byte[] passwordSalt)
		{
			using (var h = new HMACSHA512(passwordSalt))
			{
				var hash = h.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
				return hash.SequenceEqual(passwordHash);
			}
		}

	        public async Task<string> LogoutUser()
        	{
			var res = await _userRepository.Logout();
			return res;
        	}
    }
}
