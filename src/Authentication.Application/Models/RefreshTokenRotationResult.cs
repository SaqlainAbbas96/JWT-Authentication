namespace Authentication.Application.Models
{
    public sealed record RefreshTokenRotationResult(
        int UserId,
        string AccessToken,
        string RefreshToken,
        DateTime AccessTokenExpiresAt);
}
