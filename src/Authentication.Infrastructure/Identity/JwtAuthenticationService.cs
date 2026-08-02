using Authentication.Application.Interfaces;
using System.Security.Claims;
using System.Text;
using Authentication.Application.Configuration;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;

namespace Authentication.Infrastructure.Identity
{
    public class JwtAuthenticationService : IJwtAuthenticationService
    {
        private readonly JwtOptions _jwtOptions;

        public JwtAuthenticationService(IOptions<JwtOptions> jwtOptions)
        {
            _jwtOptions = jwtOptions.Value;
        }

        public string GenerateToken(string username, string userrole)
        {
            var tokenHandler = new JwtSecurityTokenHandler();

            var keyBytes = Encoding.UTF8.GetBytes(_jwtOptions.Key);
            Console.WriteLine($"Key length: {keyBytes.Length} bytes");
            Console.WriteLine($"Key: {Convert.ToBase64String(keyBytes)}");

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[]
                {
                    new Claim(ClaimTypes.Name, username),
                    new Claim(ClaimTypes.Role, "user")
                }),

                Expires = DateTime.UtcNow.AddDays(1),
                Issuer = _jwtOptions.Issuer,
                Audience = _jwtOptions.Audience,
                SigningCredentials = new SigningCredentials(
                    new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtOptions.Key)),
                    SecurityAlgorithms.HmacSha512Signature)
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);
            var returnToken = tokenHandler.WriteToken(token);

            return returnToken;
        }
    }
}
