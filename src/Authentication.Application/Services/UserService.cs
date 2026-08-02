using Authentication.Application.Dtos;
using Authentication.Application.Interfaces;
using Authentication.Domain.Entities;
using System.Security.Cryptography;

namespace Authentication.Application.Services
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
            if (string.IsNullOrEmpty(userDto.Email))
                return "Please provide your email";

            User user = new User();

            PasswordHash(userDto.Password, out byte[] passwordHash, out byte[] passwordSalt);

            user.Email = userDto.Email;
            user.PasswordHash = passwordHash;
            user.PasswordSalt = passwordSalt;

            var res = await _userRepository.RegisterUser(user);
            return res;
        }

        public async Task<string> Authenticate(LoginDto loginDto)
        {
            var user = await _userRepository.Checkuser(loginDto.Email, loginDto.Password);

            if (user is not null)
            {
                var userRole = await _userRepository.GetRole(user.Id);

                bool isPasswordCorrect = VerifyHashPassword(loginDto.Password, user.PasswordHash, user.PasswordSalt);
                return isPasswordCorrect ? _jwtAuthenticationService.GenerateToken(loginDto.Email, userRole) : "Invalid Password";
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

        public bool VerifyHashPassword(string password, byte[] passwordHash, byte[] passwordSalt)
        {
            using (var h = new HMACSHA512(passwordSalt))
            {
                var hash = h.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
                return hash.SequenceEqual(passwordHash);
            }
        }
    }
}
