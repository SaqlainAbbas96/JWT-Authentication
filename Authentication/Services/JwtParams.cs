namespace Authentication.Services
{
    public class JwtParams : IJwtParams
    {
        private readonly IConfiguration _configuration;

        public JwtParams(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        public string GetJwtKey() => _configuration["Jwt:Key"];
        public string GetJwtAudience() => _configuration["Jwt:Audience"];
        public string GetJwtIssuer() => _configuration["Jwt:Issuer"];
    }
}
