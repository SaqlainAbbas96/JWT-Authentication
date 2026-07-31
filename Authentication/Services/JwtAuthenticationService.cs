using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace Authentication.Services
{
    public class JwtAuthenticationService : IJwtAuthenticationService
    {
        private readonly IJwtParams _jwtParams;
        public JwtAuthenticationService(IJwtParams jwtParams)
        {
            _jwtParams = jwtParams;
        }

        public string GenerateToken(string username, string userrole)
        {
            var tokenHandler = new JwtSecurityTokenHandler();

            var keyBytes = Encoding.UTF8.GetBytes(_jwtParams.GetJwtKey());
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
                Issuer = _jwtParams.GetJwtIssuer(),
                Audience = _jwtParams.GetJwtAudience(),
                SigningCredentials = new SigningCredentials(
                    new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtParams.GetJwtKey())),
                    SecurityAlgorithms.HmacSha512Signature)
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);
            var returnToken = tokenHandler.WriteToken(token);

            return returnToken;
        }
    }
}
