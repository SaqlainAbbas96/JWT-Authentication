using Authentication.Application.Configuration;
using Authentication.Application.Exceptions;
using Authentication.Application.Interfaces;
using Authentication.Application.Models;
using Authentication.Domain.Entities;
using Authentication.Infrastructure.Persistence;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System.Security.Cryptography;
using System.Text;

namespace Authentication.Infrastructure.Security;

public sealed class RefreshTokenService : IRefreshTokenService
{
    private const int TokenSizeInBytes = 64;

    private readonly DBContext _db;
    private readonly JwtOptions _jwtOptions;
    private readonly IJwtAuthenticationService _jwtAuthenticationService;
    private readonly ILogger<RefreshTokenService> _logger;

    public RefreshTokenService(
        DBContext db,
        IOptions<JwtOptions> jwtOptions,
        IJwtAuthenticationService jwtAuthenticationService,
        ILogger<RefreshTokenService> logger)
    {
        _db = db;
        _jwtOptions = jwtOptions.Value;
        _jwtAuthenticationService = jwtAuthenticationService;
        _logger = logger;
    }

    public RefreshTokenResult GenerateToken()
    {
        var createdAt = DateTime.UtcNow;

        var tokenBytes =
            RandomNumberGenerator.GetBytes(
                TokenSizeInBytes);

        var token =
            WebEncoders.Base64UrlEncode(
                tokenBytes);

        var tokenHash =
            ComputeHash(token);

        var familyId = Guid.NewGuid();

        var expiresAt =
            createdAt.AddDays(
                _jwtOptions.RefreshTokenExpirationDays);

        return new RefreshTokenResult(
            token,
            tokenHash,
            familyId,
            createdAt,
            expiresAt);
    }

    public async Task<RefreshTokenRotationResult> RotateTokenAsync(
        string refreshToken,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(refreshToken))
        {
            throw new UnauthorizedException(
                "Invalid refresh token.");
        }

        var tokenHash =
            ComputeHash(refreshToken);

        int userId;
        string userEmail;
        string userRole;
        string newRefreshToken;
        Guid tokenFamilyId;

        await using var transaction =
            await _db.Database.BeginTransactionAsync(
                cancellationToken);

        try
        {
            var storedToken =
                await _db.refresh_tokens
                    .FromSqlInterpolated($"""
                        SELECT *
                        FROM refresh_tokens
                        WHERE token_hash = {tokenHash}
                        FOR UPDATE
                        """)
                    .SingleOrDefaultAsync(
                        cancellationToken);

            if (storedToken is null)
            {
                _logger.LogWarning(
                    "Refresh token authentication failed. Reason: Invalid token.");

                throw new UnauthorizedException(
                    "Invalid refresh token.");
            }

            tokenFamilyId =
                storedToken.family_id;

            if (storedToken.revoked_at is not null)
            {
                _logger.LogWarning(
                    "Refresh token reuse detected. UserId: {UserId}, TokenFamilyId: {TokenFamilyId}.",
                    storedToken.user_id,
                    storedToken.family_id);

                await RevokeTokenFamilyAsync(
                    storedToken.family_id,
                    cancellationToken);

                await transaction.CommitAsync(
                    cancellationToken);

                throw new UnauthorizedException(
                    "Invalid refresh token.");
            }

            if (storedToken.expires_at <= DateTime.UtcNow)
            {
                _logger.LogWarning(
                    "Refresh token authentication failed. UserId: {UserId}, TokenFamilyId: {TokenFamilyId}, Reason: Expired token.",
                    storedToken.user_id,
                    storedToken.family_id);

                storedToken.revoked_at =
                    DateTime.UtcNow;

                await _db.SaveChangesAsync(
                    cancellationToken);

                await transaction.CommitAsync(
                    cancellationToken);

                throw new UnauthorizedException(
                    "Invalid refresh token.");
            }

            var userData =
                await _db.user_roles
                    .Where(ur =>
                        ur.user_id ==
                        storedToken.user_id)
                    .Join(
                        _db.roles,
                        ur => ur.role_id,
                        role => role.id,
                        (ur, role) => new
                        {
                            role.role_name
                        })
                    .FirstOrDefaultAsync(
                        cancellationToken);

            if (userData is null ||
                string.IsNullOrWhiteSpace(
                    userData.role_name))
            {
                _logger.LogWarning(
                    "Refresh token authentication failed. UserId: {UserId}, TokenFamilyId: {TokenFamilyId}, Reason: User role is not configured.",
                    storedToken.user_id,
                    storedToken.family_id);

                throw new UnauthorizedException(
                    "Invalid refresh token.");
            }

            var email =
                await _db.users
                    .Where(user =>
                        user.id ==
                        storedToken.user_id)
                    .Select(user => user.email)
                    .SingleOrDefaultAsync(
                        cancellationToken);

            if (string.IsNullOrWhiteSpace(email))
            {
                _logger.LogWarning(
                    "Refresh token authentication failed. UserId: {UserId}, TokenFamilyId: {TokenFamilyId}, Reason: User is not configured.",
                    storedToken.user_id,
                    storedToken.family_id);

                throw new UnauthorizedException(
                    "Invalid refresh token.");
            }

            var newRefreshTokenResult =
                GenerateToken(
                    storedToken.family_id);

            var replacementToken =
                new RefreshToken
                {
                    user_id =
                        storedToken.user_id,

                    token_hash =
                        newRefreshTokenResult.TokenHash,

                    family_id =
                        newRefreshTokenResult.FamilyId,

                    created_at =
                        newRefreshTokenResult.CreatedAt,

                    expires_at =
                        newRefreshTokenResult.ExpiresAt
                };

            _db.refresh_tokens.Add(
                replacementToken);

            await _db.SaveChangesAsync(
                cancellationToken);

            storedToken.revoked_at =
                DateTime.UtcNow;

            storedToken.replaced_by_token_id =
                replacementToken.id;

            await _db.SaveChangesAsync(
                cancellationToken);

            userId =
                storedToken.user_id;

            userEmail =
                email;

            userRole =
                userData.role_name;

            newRefreshToken =
                newRefreshTokenResult.Token;

            await transaction.CommitAsync(
                cancellationToken);

            _logger.LogInformation(
                "Refresh token rotated successfully. UserId: {UserId}, TokenFamilyId: {TokenFamilyId}.",
                userId,
                tokenFamilyId);
        }
        catch
        {
            if (_db.Database.CurrentTransaction is not null)
            {
                await transaction.RollbackAsync(
                    CancellationToken.None);
            }

            throw;
        }

        var (accessToken, expiresAt) =
            _jwtAuthenticationService.GenerateToken(
                userId,
                userEmail,
                userRole);

        return new RefreshTokenRotationResult(
            userId,
            accessToken,
            newRefreshToken,
            expiresAt);
    }

    public async Task RevokeTokenFamilyAsync(
        string refreshToken,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(refreshToken))
        {
            return;
        }

        var tokenHash =
            ComputeHash(refreshToken);

        var storedToken =
            await _db.refresh_tokens
                .AsNoTracking()
                .Where(rt =>
                    rt.token_hash ==
                    tokenHash)
                .Select(rt => new
                {
                    rt.user_id,
                    rt.family_id
                })
                .SingleOrDefaultAsync(
                    cancellationToken);

        if (storedToken is null)
        {
            _logger.LogWarning(
                "Refresh token revocation requested for an invalid token.");

            return;
        }

        await using var transaction =
            await _db.Database.BeginTransactionAsync(
                cancellationToken);

        try
        {
            await RevokeTokenFamilyAsync(
                storedToken.family_id,
                cancellationToken);

            await transaction.CommitAsync(
                cancellationToken);

            _logger.LogInformation(
                "Refresh token family revoked. UserId: {UserId}, TokenFamilyId: {TokenFamilyId}.",
                storedToken.user_id,
                storedToken.family_id);
        }
        catch
        {
            if (_db.Database.CurrentTransaction is not null)
            {
                await transaction.RollbackAsync(
                    CancellationToken.None);
            }

            throw;
        }
    }

    private RefreshTokenResult GenerateToken(
        Guid familyId)
    {
        var createdAt =
            DateTime.UtcNow;

        var tokenBytes =
            RandomNumberGenerator.GetBytes(
                TokenSizeInBytes);

        var token =
            WebEncoders.Base64UrlEncode(
                tokenBytes);

        var tokenHash =
            ComputeHash(token);

        var expiresAt =
            createdAt.AddDays(
                _jwtOptions.RefreshTokenExpirationDays);

        return new RefreshTokenResult(
            token,
            tokenHash,
            familyId,
            createdAt,
            expiresAt);
    }

    private async Task RevokeTokenFamilyAsync(
        Guid familyId,
        CancellationToken cancellationToken)
    {
        var tokens =
            await _db.refresh_tokens
                .Where(rt =>
                    rt.family_id == familyId &&
                    rt.revoked_at == null)
                .ToListAsync(
                    cancellationToken);

        var revokedAt =
            DateTime.UtcNow;

        foreach (var token in tokens)
        {
            token.revoked_at =
                revokedAt;
        }

        await _db.SaveChangesAsync(
            cancellationToken);
    }

    private static string ComputeHash(
        string token)
    {
        var tokenBytes =
            Encoding.UTF8.GetBytes(token);

        var hash =
            SHA256.HashData(tokenBytes);

        return Convert.ToHexString(hash)
            .ToLowerInvariant();
    }
}