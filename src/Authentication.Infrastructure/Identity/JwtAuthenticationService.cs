using Authentication.Application.Configuration;
using Authentication.Application.Interfaces;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace Authentication.Infrastructure.Identity
{
    public class JwtAuthenticationService : IJwtAuthenticationService
    {
        private readonly JwtOptions _jwtOptions;

        public JwtAuthenticationService(IOptions<JwtOptions> jwtOptions)
        {
            _jwtOptions = jwtOptions.Value;
        }

        public (string AccessToken, DateTime ExpiresAt) GenerateToken(
           int userId,
           string email,
           string role)
        {
            var now = DateTime.UtcNow;

            var expiresAt = now.AddMinutes(
                _jwtOptions.AccessTokenExpirationMinutes);

            var claims = new[]
            {
                new Claim(
                    JwtRegisteredClaimNames.Sub,
                    userId.ToString()),

                new Claim(
                    JwtRegisteredClaimNames.Jti,
                    Guid.NewGuid().ToString()),

                new Claim(
                    JwtRegisteredClaimNames.Iat,
                    new DateTimeOffset(now).ToUnixTimeSeconds().ToString(),
                    ClaimValueTypes.Integer64),

                new Claim(
                    ClaimTypes.Name,
                    email),

                new Claim(
                    ClaimTypes.Role,
                    role)
            };

            var signingKey = new SymmetricSecurityKey(
                Convert.FromBase64String(_jwtOptions.Key));

            var credentials = new SigningCredentials(
                signingKey,
                SecurityAlgorithms.HmacSha512);

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),
                Expires = expiresAt,
                Issuer = _jwtOptions.Issuer,
                Audience = _jwtOptions.Audience,
                SigningCredentials = credentials
            };

            var tokenHandler = new JwtSecurityTokenHandler();

            var token = tokenHandler.CreateToken(tokenDescriptor);

            return (
                tokenHandler.WriteToken(token),
                expiresAt);
        }
    }
}
