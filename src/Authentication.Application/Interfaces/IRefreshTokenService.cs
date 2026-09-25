using Authentication.Application.Models;

namespace Authentication.Application.Interfaces
{
    public interface IRefreshTokenService
    {
        RefreshTokenResult GenerateToken();

        Task<RefreshTokenRotationResult> RotateTokenAsync(
            string refreshToken,
            CancellationToken cancellationToken);

        Task RevokeTokenFamilyAsync(
            string refreshToken,
            CancellationToken cancellationToken);
    }
}
