using OAuth.Models;
using OAuth.Models.Dtos;

namespace OAuth.Repositories
{
	public class UserRepository : IUserRepository
	{
		private readonly DBContext _db;
        	private readonly IHttpContextAccessor _httpContextAccessor;
        	public UserRepository(DBContext db, IHttpContextAccessor httpContextAccessor)
        	{
	            _db = db;
        	    _httpContextAccessor = httpContextAccessor;
	        }

        	public async Task<string> RegisterUser(User user)
		{
			_db.User.Add(user);
			await _db.SaveChangesAsync();

			return "User registered successfully";
		}

		public async Task<string?> GetRole(int userId)
		{
			int roleId = _db.UserRoles.Where(u => u.userId == userId).Select(u => u.roleId).FirstOrDefault();
			string role = _db.Role.Where(r => r.id == roleId).Select(r => r.rolename).FirstOrDefault();
			return role;
		}

		public async Task<User?> Checkuser(string email, string password)
		{
			var user = _db.User.FirstOrDefault(u => u.email == email);

			return user != null ? user : null;
		}

        	public async Task<string> Logout()
        	{
            		// Clear authentication tokens
            		//_httpContextAccessor.HttpContext.Response.Cookies.Delete("authenticationToken");

            		// Clear session data
            		_httpContextAccessor.HttpContext.Session.Clear();

			return "Logout Successfully";
	        }
    }
}
