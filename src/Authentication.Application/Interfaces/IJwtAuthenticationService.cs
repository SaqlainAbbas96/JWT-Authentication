namespace Authentication.Application.Interfaces
{
	public interface IJwtAuthenticationService
	{
		string GenerateToken(string username, string userrole);
	}
}
