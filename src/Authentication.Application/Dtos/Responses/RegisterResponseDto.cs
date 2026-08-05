namespace Authentication.Application.Dtos.Responses
{
    public class RegisterResponseDto
    {
        public int UserId { get; set; }
        public string Email { get; set; } = default!;
        public string Message { get; set; } = "User registered successfully.";
    }
}
