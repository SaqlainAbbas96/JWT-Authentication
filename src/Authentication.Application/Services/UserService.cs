using Authentication.Application.Dtos.Requests;
using Authentication.Application.Dtos.Responses;
using Authentication.Application.Interfaces;
using Authentication.Domain.Entities;

namespace Authentication.Application.Services
{
    public class UserService : IUserService
    {
        private readonly IUserRepository _userRepository;
        private readonly IJwtAuthenticationService _jwtAuthenticationService;
        private readonly IPasswordHasher _passwordHasher;
        public UserService(IUserRepository userRepository, IJwtAuthenticationService jwtAuthenticationService, IPasswordHasher passwordHasher)
        {
            _jwtAuthenticationService = jwtAuthenticationService;
            _userRepository = userRepository;
            _passwordHasher = passwordHasher;
        }

        public async Task<RegisterResponseDto> RegisterUser(RegisterRequestDto request)
        {
            if (string.IsNullOrWhiteSpace(request.Email))
                throw new ArgumentException("Email is required.");

            if (string.IsNullOrWhiteSpace(request.Password))
                throw new ArgumentException("Password is required.");

            User user = new User();

            var (hash, salt) = _passwordHasher.HashPassword(request.Password);

            user.email = request.Email;
            user.password_hash = hash;
            user.password_salt = salt;

            var res = await _userRepository.RegisterUser(user);
            
            return new RegisterResponseDto
            {
                UserId = user.id,
                Email = user.email,
                Message = "User registered successfully."
            };
        }

        public async Task<LoginResponseDto> Authenticate(LoginRequestDto request)
        {
            if (string.IsNullOrWhiteSpace(request.Email))
                throw new ArgumentException("Email is required.");

            if (string.IsNullOrWhiteSpace(request.Password))
                throw new ArgumentException("Password is required.");

            var user = await _userRepository.CheckUser(request.Email);

            if (user is null)
                throw new UnauthorizedAccessException("Invalid credentials.");

            var valid = _passwordHasher.VerifyPassword(
                request.Password,
                user.password_hash,
                user.password_salt);

            if (!valid)
                throw new UnauthorizedAccessException("Invalid credentials.");
    
            var userRole = await _userRepository.GetRole(user.id);

            var token = _jwtAuthenticationService.GenerateToken(request.Email, userRole);

            return new LoginResponseDto
            {
                AccessToken = token,
                TokenType = "Bearer",
                ExpiresAt = DateTime.UtcNow.AddDays(1)
            };
        }
    }
}
