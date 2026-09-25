using Authentication.Application.Dtos.Requests;
using Authentication.Application.Dtos.Responses;
using Authentication.Application.Exceptions;
using Authentication.Application.Interfaces;
using Authentication.Domain.Entities;

namespace Authentication.Application.Services
{
    public class UserService : IUserService
    {
        private readonly IUserRepository _userRepository;
        private readonly IJwtAuthenticationService _jwtAuthenticationService;
        private readonly IPasswordHasher _passwordHasher;
        private readonly IRefreshTokenService _refreshTokenService;
        public UserService(
            IUserRepository userRepository, 
            IJwtAuthenticationService jwtAuthenticationService, 
            IPasswordHasher passwordHasher,
            IRefreshTokenService refreshTokenService)
        {
            _jwtAuthenticationService = jwtAuthenticationService;
            _userRepository = userRepository;
            _passwordHasher = passwordHasher;
            _refreshTokenService = refreshTokenService;
        }

        public async Task<RegisterResponseDto> RegisterUser(
            RegisterRequestDto request, 
            CancellationToken cancellationToken)
        {
            if (await _userRepository.EmailExists(
                    request.Email,
                    cancellationToken))
            {
                throw new ConflictException(
                    "Email is already registered.");
            }

            var (hash, salt) = _passwordHasher.HashPassword(request.Password);

            User user = new User
            {
                email = request.Email,
                password_hash = hash,
                password_salt = salt
            };

            await _userRepository.RegisterUser(
                user, 
                "user",
                cancellationToken);

            return new RegisterResponseDto
            {
                UserId = user.id,
                Email = user.email,
                Message = "User registered successfully."
            };
        }

        public async Task<LoginResponseDto> Authenticate(
            LoginRequestDto request,
            CancellationToken cancellationToken)
        {
            var user = 
                await _userRepository.CheckUser(
                    request.Email,
                    cancellationToken);

            if (user is null)
            {
                throw new UnauthorizedException(
                    "Invalid email or password.");
            }

            var passwordValid = _passwordHasher.VerifyPassword(
                request.Password,
                user.password_hash,
                user.password_salt);

            if (!passwordValid)
            {
                throw new UnauthorizedException(
                    "Invalid email or password.");
            }

            var userRole = 
                await _userRepository.GetRole(
                    user.id, 
                    cancellationToken);

            if (string.IsNullOrWhiteSpace(userRole))
            {
                throw new UnauthorizedException(
                    "User role is not configured.");
            }

            var (accessToken, expiresAt) =
                _jwtAuthenticationService.GenerateToken(
                    user.id,
                    user.email,
                    userRole);

            var refreshTokenResult = 
                _refreshTokenService.GenerateToken();

            var refreshToken = new RefreshToken
            {
                user_id = user.id,
                token_hash = refreshTokenResult.TokenHash,
                family_id = refreshTokenResult.FamilyId,
                created_at = refreshTokenResult.CreatedAt,
                expires_at = refreshTokenResult.ExpiresAt
            };

            await _userRepository.CreateRefreshToken(
                refreshToken,
                cancellationToken);

            return new LoginResponseDto
            {
                AccessToken = accessToken,
                RefreshToken = refreshTokenResult.Token,
                TokenType = "Bearer",
                ExpiresAt = expiresAt
            };
        }
    }
}
