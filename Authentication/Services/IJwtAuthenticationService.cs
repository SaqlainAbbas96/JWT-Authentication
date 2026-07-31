namespace Authentication.Services
{
	public interface IJwtAuthenticationService
	{
		string GenerateToken(string username, string userrole);
	}
}
