using Authentication.Application.Models;

namespace Authentication.Application.Interfaces
{
    public interface IRefreshTokenService
    {
        RefreshTokenResult GenerateToken();
        Task<RefreshTokenRotationResult> RotateTokenAsync(string refreshToken);
        Task RevokeTokenFamilyAsync(string refreshToken);
    }
}
