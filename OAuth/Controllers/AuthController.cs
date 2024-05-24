using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using OAuth.Models;
using OAuth.Models.Dtos;
using OAuth.Services;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace OAuth.Controllers
{
	[Route("api/[controller]")]
	[ApiController]
	public class AuthController : ControllerBase
	{
		private readonly IUserService _userService;
		public AuthController(IUserService userService)
		{
			_userService = userService;
		}

		[HttpPost("Register")]
		public async Task<ActionResult<User>> Register([FromBody] UserDto userDto)
		{
			var res = await _userService.RegisterUser(userDto);
			return Ok(res);
		}

		[HttpPost("Login")]
		public async Task<ActionResult<string>> Login([FromBody] LoginDto loginDto)
		{
			JwtSecurityTokenHandler tokenHandler = new JwtSecurityTokenHandler();

			string value = await _userService.Authenticate(loginDto);
			var isValidJwt = tokenHandler.CanReadToken(value);

			if (isValidJwt)
			{
				return Ok(value);
			}

			return Unauthorized(value);
		}

		[HttpPost("Logout")]
		public async Task<ActionResult> Logout()
        {
            var res = await _userService.LogoutUser();
            return Ok(res);
        }
	}
}
