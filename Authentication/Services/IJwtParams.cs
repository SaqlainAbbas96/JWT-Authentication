namespace Authentication.Services
{
	public interface IJwtParams
	{
		string GetJwtKey();
		string GetJwtAudience();
		string GetJwtIssuer();
	}
}
