namespace Authentication.Application.Dtos.Responses
{
    public class LoginResponseDto
    {
        public string AccessToken { get; set; } = default!;
        public string TokenType { get; set; } = "Bearer";
        public DateTime ExpiresAt { get; set; }
    }
}
