using Authentication.Application.Dtos.Requests;
using Authentication.Application.Dtos.Responses;

namespace Authentication.Application.Interfaces
{
	public interface IUserService
	{
        Task<RegisterResponseDto> RegisterUser(RegisterRequestDto request);
        Task<LoginResponseDto> Authenticate(LoginRequestDto request);
    }
}
