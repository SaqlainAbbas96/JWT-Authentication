namespace Authentication.Application.Models
{
    public sealed record RefreshTokenResult(
        string Token,
        string TokenHash,
        Guid FamilyId,
        DateTime CreatedAt,
        DateTime ExpiresAt);
}
