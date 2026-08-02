using Authentication.Application.Dtos;
using Authentication.Application.Interfaces;
using Microsoft.AspNetCore.Mvc;
using System.IdentityModel.Tokens.Jwt;

namespace Authentication.Api.Controllers
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
        public async Task<ActionResult<string>> Register([FromBody] UserDto userDto)
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
    }
}
