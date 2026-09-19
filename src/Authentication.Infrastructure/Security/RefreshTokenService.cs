using Authentication.Application.Configuration;
using Authentication.Application.Exceptions;
using Authentication.Application.Interfaces;
using Authentication.Application.Models;
using Authentication.Domain.Entities;
using Authentication.Infrastructure.Persistence;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using System.Security.Cryptography;
using System.Text;

namespace Authentication.Infrastructure.Security
{
    public sealed class RefreshTokenService : IRefreshTokenService
    {
        private const int TokenSizeInBytes = 64;

        private readonly DBContext _db;
        private readonly JwtOptions _jwtOptions;
        private readonly IJwtAuthenticationService _jwtAuthenticationService;

        public RefreshTokenService(
            DBContext db,
            IOptions<JwtOptions> jwtOptions,
            IJwtAuthenticationService jwtAuthenticationService)
        {
            _db = db;
            _jwtOptions = jwtOptions.Value;
            _jwtAuthenticationService = jwtAuthenticationService;
        }

        public RefreshTokenResult GenerateToken()
        {
            var createdAt = DateTime.UtcNow;

            var tokenBytes = RandomNumberGenerator.GetBytes(
                TokenSizeInBytes);

            var token = WebEncoders.Base64UrlEncode(tokenBytes);

            var tokenHash = ComputeHash(token);

            var familyId = Guid.NewGuid();

            var expiresAt = createdAt.AddDays(
                _jwtOptions.RefreshTokenExpirationDays);

            return new RefreshTokenResult(
                token,
                tokenHash,
                familyId,
                createdAt,
                expiresAt);
        }

        public async Task<RefreshTokenRotationResult> RotateTokenAsync(string refreshToken)
        {
            if (string.IsNullOrWhiteSpace(refreshToken))
            {
                throw new UnauthorizedException(
                    "Invalid refresh token.");
            }

            var tokenHash = ComputeHash(refreshToken);

            int userId;
            string userEmail;
            string userRole;
            string newRefreshToken;

            await using var transaction =
                await _db.Database.BeginTransactionAsync();

            try
            {
                var storedToken = await _db.refresh_tokens
                    .FromSqlInterpolated($"""
                        SELECT *
                        FROM refresh_tokens
                        WHERE token_hash = {tokenHash}
                        FOR UPDATE
                        """)
                    .SingleOrDefaultAsync();

                if (storedToken is null)
                {
                    throw new UnauthorizedException(
                        "Invalid refresh token.");
                }

                if (storedToken.revoked_at is not null)
                {
                    await RevokeTokenFamilyAsync(
                        storedToken.family_id);

                    await transaction.CommitAsync();

                    throw new UnauthorizedException(
                        "Invalid refresh token.");
                }

                if (storedToken.expires_at <= DateTime.UtcNow)
                {
                    storedToken.revoked_at = DateTime.UtcNow;

                    await _db.SaveChangesAsync();
                    await transaction.CommitAsync();

                    throw new UnauthorizedException(
                        "Refresh token has expired.");
                }

                var userData = await _db.user_roles
                    .Where(ur => ur.user_id == storedToken.user_id)
                    .Join(
                        _db.roles,
                        ur => ur.role_id,
                        role => role.id,
                        (ur, role) => new
                        {
                            role.role_name
                        })
                    .FirstOrDefaultAsync();

                if (userData is null ||
                    string.IsNullOrWhiteSpace(userData.role_name))
                {
                    throw new UnauthorizedException(
                        "User role is not configured.");
                }

                var email = await _db.users
                    .Where(user => user.id == storedToken.user_id)
                    .Select(user => user.email)
                    .SingleOrDefaultAsync();

                if (string.IsNullOrWhiteSpace(email))
                {
                    throw new UnauthorizedException(
                        "User is not configured.");
                }

                var newRefreshTokenResult = GenerateToken(
                    storedToken.family_id);

                var replacementToken = new RefreshToken
                {
                    user_id = storedToken.user_id,
                    token_hash = newRefreshTokenResult.TokenHash,
                    family_id = newRefreshTokenResult.FamilyId,
                    created_at = newRefreshTokenResult.CreatedAt,
                    expires_at = newRefreshTokenResult.ExpiresAt
                };

                _db.refresh_tokens.Add(replacementToken);

                await _db.SaveChangesAsync();

                storedToken.revoked_at = DateTime.UtcNow;
                storedToken.replaced_by_token_id =
                    replacementToken.id;

                await _db.SaveChangesAsync();

                userId = storedToken.user_id;
                userEmail = email;
                userRole = userData.role_name;
                newRefreshToken = newRefreshTokenResult.Token;

                await transaction.CommitAsync();
            }
            catch
            {
                if (_db.Database.CurrentTransaction is not null)
                {
                    await transaction.RollbackAsync();
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

        public async Task RevokeTokenFamilyAsync(string refreshToken)
        {
            if (string.IsNullOrWhiteSpace(refreshToken))
            {
                return;
            }

            var tokenHash = ComputeHash(refreshToken);

            var storedToken = await _db.refresh_tokens
                .AsNoTracking()
                .Where(rt => rt.token_hash == tokenHash)
                .Select(rt => new
                {
                    rt.family_id
                })
                .SingleOrDefaultAsync();

            if (storedToken is null)
            {
                return;
            }

            await using var transaction =
                await _db.Database.BeginTransactionAsync();

            try
            {
                await RevokeTokenFamilyAsync(
                    storedToken.family_id);

                await transaction.CommitAsync();
            }
            catch
            {
                if (_db.Database.CurrentTransaction is not null)
                {
                    await transaction.RollbackAsync();
                }

                throw;
            }
        }

        private RefreshTokenResult GenerateToken(Guid familyId)
        {
            var createdAt = DateTime.UtcNow;

            var tokenBytes = RandomNumberGenerator.GetBytes(
                TokenSizeInBytes);

            var token = WebEncoders.Base64UrlEncode(tokenBytes);

            var tokenHash = ComputeHash(token);

            var expiresAt = createdAt.AddDays(
                _jwtOptions.RefreshTokenExpirationDays);

            return new RefreshTokenResult(
                token,
                tokenHash,
                familyId,
                createdAt,
                expiresAt);
        }

        private async Task RevokeTokenFamilyAsync(Guid familyId)
        {
            var tokens = await _db.refresh_tokens
                .Where(rt => rt.family_id == familyId &&
                             rt.revoked_at == null)
                .ToListAsync();

            var revokedAt = DateTime.UtcNow;

            foreach (var token in tokens)
            {
                token.revoked_at = revokedAt;
            }

            await _db.SaveChangesAsync();
        }

        private async Task<string> GetUserEmailAsync(int userId)
        {
            var email = await _db.users
                .Where(user => user.id == userId)
                .Select(user => user.email)
                .SingleOrDefaultAsync();

            if (string.IsNullOrWhiteSpace(email))
            {
                throw new UnauthorizedException(
                    "User is not configured.");
            }

            return email;
        }

        private static string ComputeHash(string token)
        {
            var tokenBytes = Encoding.UTF8.GetBytes(token);

            var hash = SHA256.HashData(tokenBytes);

            return Convert.ToHexString(hash).ToLowerInvariant();
        }
    }
}
