namespace Authentication.Application.Configuration
{
    public class JwtOptions
    {
        public string Key { get; init; } = default!;
        public string Issuer { get; init; } = default!;
        public string Audience { get; init; } = default!;
    }
}
