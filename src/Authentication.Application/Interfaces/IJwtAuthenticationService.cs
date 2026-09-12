namespace Authentication.Application.Interfaces
{
	public interface IJwtAuthenticationService
	{
        (string AccessToken, DateTime ExpiresAt) GenerateToken(
            int userId,
            string email,
            string role);
    }
}
