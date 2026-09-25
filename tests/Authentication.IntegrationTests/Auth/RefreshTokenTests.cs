using Authentication.IntegrationTests.Infrastructure;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;

namespace Authentication.IntegrationTests.Auth;

public sealed class RefreshTokenTests
    : IClassFixture<PostgreSqlFixture>,
      IAsyncLifetime
{
    private readonly PostgreSqlFixture _postgresFixture;

    private AuthenticationWebApplicationFactory _factory = null!;
    private HttpClient _client = null!;

    public RefreshTokenTests(
        PostgreSqlFixture postgresFixture)
    {
        _postgresFixture = postgresFixture;
    }

    public ValueTask InitializeAsync()
    {
        _factory = new AuthenticationWebApplicationFactory(
            _postgresFixture.ConnectionString);

        _client = _factory.CreateClient();

        return ValueTask.CompletedTask;
    }

    public async ValueTask DisposeAsync()
    {
        _client.Dispose();
        await _factory.DisposeAsync();
    }

    [Fact]
    public async Task RefreshToken_WithValidToken_ShouldRotateTokens()
    {
        var email =
            $"refresh-{Guid.NewGuid():N}@example.com";

        var password = "Password123!";

        var registerResponse =
            await _client.PostAsJsonAsync(
                "/api/auth/register",
                new
                {
                    email,
                    password
                });

        Assert.Equal(
            HttpStatusCode.Created,
            registerResponse.StatusCode);

        var loginResponse =
            await _client.PostAsJsonAsync(
                "/api/auth/login",
                new
                {
                    email,
                    password
                });

        Assert.Equal(
            HttpStatusCode.OK,
            loginResponse.StatusCode);

        var loginBody =
            await loginResponse.Content
                .ReadFromJsonAsync<JsonElement>();

        var originalRefreshToken =
            loginBody
                .GetProperty("refreshToken")
                .GetString();

        Assert.False(
            string.IsNullOrWhiteSpace(originalRefreshToken));

        var refreshResponse =
            await _client.PostAsJsonAsync(
                "/api/auth/refresh-token",
                new
                {
                    refreshToken = originalRefreshToken
                });

        Assert.Equal(
            HttpStatusCode.OK,
            refreshResponse.StatusCode);

        var refreshBody =
            await refreshResponse.Content
                .ReadFromJsonAsync<JsonElement>();

        var newAccessToken =
            refreshBody
                .GetProperty("accessToken")
                .GetString();

        var newRefreshToken =
            refreshBody
                .GetProperty("refreshToken")
                .GetString();

        var tokenType =
            refreshBody
                .GetProperty("tokenType")
                .GetString();

        var expiresAt =
            refreshBody
                .GetProperty("expiresAt")
                .GetDateTime();

        Assert.False(
            string.IsNullOrWhiteSpace(newAccessToken));

        Assert.False(
            string.IsNullOrWhiteSpace(newRefreshToken));

        Assert.NotEqual(
            originalRefreshToken,
            newRefreshToken);

        Assert.Equal(
            "Bearer",
            tokenType);

        Assert.True(
            expiresAt > DateTime.UtcNow);
    }

    [Fact]
    public async Task RefreshToken_WhenReusedAfterRotation_ShouldReturnUnauthorized()
    {
        var email =
            $"refresh-reuse-{Guid.NewGuid():N}@example.com";

        var password = "Password123!";

        var registerResponse =
            await _client.PostAsJsonAsync(
                "/api/auth/register",
                new
                {
                    email,
                    password
                });

        Assert.Equal(
            HttpStatusCode.Created,
            registerResponse.StatusCode);

        var loginResponse =
            await _client.PostAsJsonAsync(
                "/api/auth/login",
                new
                {
                    email,
                    password
                });

        Assert.Equal(
            HttpStatusCode.OK,
            loginResponse.StatusCode);

        var loginBody =
            await loginResponse.Content
                .ReadFromJsonAsync<JsonElement>();

        var originalRefreshToken =
            loginBody
                .GetProperty("refreshToken")
                .GetString();

        Assert.False(
            string.IsNullOrWhiteSpace(originalRefreshToken));

        var firstRefreshResponse =
            await _client.PostAsJsonAsync(
                "/api/auth/refresh-token",
                new
                {
                    refreshToken = originalRefreshToken
                });

        Assert.Equal(
            HttpStatusCode.OK,
            firstRefreshResponse.StatusCode);

        var reuseResponse =
            await _client.PostAsJsonAsync(
                "/api/auth/refresh-token",
                new
                {
                    refreshToken = originalRefreshToken
                });

        Assert.Equal(
            HttpStatusCode.Unauthorized,
            reuseResponse.StatusCode);

        var problemDetails =
            await reuseResponse.Content
                .ReadFromJsonAsync<JsonElement>();

        Assert.Equal(
            401,
            problemDetails.GetProperty("status").GetInt32());

        Assert.Equal(
            "Unauthorized",
            problemDetails.GetProperty("title").GetString());

        Assert.False(
            string.IsNullOrWhiteSpace(
                problemDetails.GetProperty("detail").GetString()));

        Assert.True(
            problemDetails.TryGetProperty(
                "traceId",
                out _));
    }

    [Fact]
    public async Task RefreshToken_WhenReuseIsDetected_ShouldRevokeEntireTokenFamily()
    {
        var email =
            $"refresh-family-{Guid.NewGuid():N}@example.com";

        var password = "Password123!";

        var registerResponse =
            await _client.PostAsJsonAsync(
                "/api/auth/register",
                new
                {
                    email,
                    password
                });

        Assert.Equal(
            HttpStatusCode.Created,
            registerResponse.StatusCode);

        var loginResponse =
            await _client.PostAsJsonAsync(
                "/api/auth/login",
                new
                {
                    email,
                    password
                });

        Assert.Equal(
            HttpStatusCode.OK,
            loginResponse.StatusCode);

        var loginBody =
            await loginResponse.Content
                .ReadFromJsonAsync<JsonElement>();

        var originalRefreshToken =
            loginBody
                .GetProperty("refreshToken")
                .GetString();

        Assert.False(
            string.IsNullOrWhiteSpace(originalRefreshToken));

        var firstRefreshResponse =
            await _client.PostAsJsonAsync(
                "/api/auth/refresh-token",
                new
                {
                    refreshToken = originalRefreshToken
                });

        Assert.Equal(
            HttpStatusCode.OK,
            firstRefreshResponse.StatusCode);

        var firstRefreshBody =
            await firstRefreshResponse.Content
                .ReadFromJsonAsync<JsonElement>();

        var rotatedRefreshToken =
            firstRefreshBody
                .GetProperty("refreshToken")
                .GetString();

        Assert.False(
            string.IsNullOrWhiteSpace(rotatedRefreshToken));

        Assert.NotEqual(
            originalRefreshToken,
            rotatedRefreshToken);

        // Reuse the already-rotated token.
        var reuseResponse =
            await _client.PostAsJsonAsync(
                "/api/auth/refresh-token",
                new
                {
                    refreshToken = originalRefreshToken
                });

        Assert.Equal(
            HttpStatusCode.Unauthorized,
            reuseResponse.StatusCode);

        // The replacement token belongs to the same family
        // and must now also be rejected.
        var familyRevokedResponse =
            await _client.PostAsJsonAsync(
                "/api/auth/refresh-token",
                new
                {
                    refreshToken = rotatedRefreshToken
                });

        Assert.Equal(
            HttpStatusCode.Unauthorized,
            familyRevokedResponse.StatusCode);

        var problemDetails =
            await familyRevokedResponse.Content
                .ReadFromJsonAsync<JsonElement>();

        Assert.Equal(
            401,
            problemDetails.GetProperty("status").GetInt32());

        Assert.Equal(
            "Unauthorized",
            problemDetails.GetProperty("title").GetString());

        Assert.False(
            string.IsNullOrWhiteSpace(
                problemDetails.GetProperty("detail").GetString()));

        Assert.True(
            problemDetails.TryGetProperty(
                "traceId",
                out _));
    }

    [Fact]
    public async Task RefreshToken_WhenExpired_ShouldReturnUnauthorized()
    {
        await using var factory =
            new AuthenticationWebApplicationFactory(
                _postgresFixture.ConnectionString,
                refreshTokenExpirationDays: 1);

        using var client =
            factory.CreateClient();

        var email =
            $"refresh-expired-{Guid.NewGuid():N}@example.com";

        var password = "Password123!";

        var registerResponse =
            await client.PostAsJsonAsync(
                "/api/auth/register",
                new
                {
                    email,
                    password
                });

        Assert.Equal(
            HttpStatusCode.Created,
            registerResponse.StatusCode);

        var loginResponse =
            await client.PostAsJsonAsync(
                "/api/auth/login",
                new
                {
                    email,
                    password
                });

        Assert.Equal(
            HttpStatusCode.OK,
            loginResponse.StatusCode);

        var loginBody =
            await loginResponse.Content
                .ReadFromJsonAsync<JsonElement>();

        var refreshToken =
            loginBody
                .GetProperty("refreshToken")
                .GetString();

        Assert.False(
            string.IsNullOrWhiteSpace(refreshToken));

        // The configured lifetime is one day.
        // We cannot realistically wait for the token to expire,
        // so the database expiry is adjusted directly for this
        // integration test.
        await using var connection =
            new Npgsql.NpgsqlConnection(
                _postgresFixture.ConnectionString);

        await connection.OpenAsync();

        const string sql = """
            UPDATE public.refresh_tokens
            SET expires_at = NOW() - INTERVAL '1 minute'
            WHERE token_hash = @tokenHash;
            """;

        var tokenHash =
            Convert.ToHexString(
                System.Security.Cryptography.SHA256.HashData(
                    System.Text.Encoding.UTF8.GetBytes(
                        refreshToken!)))
            .ToLowerInvariant();

        await using var command =
            new Npgsql.NpgsqlCommand(
                sql,
                connection);

        command.Parameters.AddWithValue(
            "tokenHash",
            tokenHash!);

        var affectedRows =
            await command.ExecuteNonQueryAsync();

        Assert.Equal(
            1,
            affectedRows);

        var refreshResponse =
            await client.PostAsJsonAsync(
                "/api/auth/refresh-token",
                new
                {
                    refreshToken
                });

        Assert.Equal(
            HttpStatusCode.Unauthorized,
            refreshResponse.StatusCode);

        var problemDetails =
            await refreshResponse.Content
                .ReadFromJsonAsync<JsonElement>();

        Assert.Equal(
            401,
            problemDetails.GetProperty("status").GetInt32());

        Assert.Equal(
            "Unauthorized",
            problemDetails.GetProperty("title").GetString());

        Assert.Equal(
            "Invalid refresh token.",
            problemDetails.GetProperty("detail").GetString());

        Assert.True(
            problemDetails.TryGetProperty(
                "traceId",
                out _));
    }

    [Fact]
    public async Task RefreshToken_WhenTokenDoesNotExist_ShouldReturnUnauthorized()
    {
        var invalidRefreshToken =
            "invalid-refresh-token-that-does-not-exist";

        var refreshResponse =
            await _client.PostAsJsonAsync(
                "/api/auth/refresh-token",
                new
                {
                    refreshToken = invalidRefreshToken
                });

        Assert.Equal(
            HttpStatusCode.Unauthorized,
            refreshResponse.StatusCode);

        var problemDetails =
            await refreshResponse.Content
                .ReadFromJsonAsync<JsonElement>();

        Assert.Equal(
            401,
            problemDetails.GetProperty("status").GetInt32());

        Assert.Equal(
            "Unauthorized",
            problemDetails.GetProperty("title").GetString());

        Assert.Equal(
            "Invalid refresh token.",
            problemDetails.GetProperty("detail").GetString());

        Assert.True(
            problemDetails.TryGetProperty(
                "traceId",
                out _));
    }

    [Fact]
    public async Task RefreshToken_WhenRefreshTokenIsMissing_ShouldReturnBadRequest()
    {
        var refreshResponse =
            await _client.PostAsJsonAsync(
                "/api/auth/refresh-token",
                new
                {
                });

        Assert.Equal(
            HttpStatusCode.BadRequest,
            refreshResponse.StatusCode);

        var problemDetails =
            await refreshResponse.Content
                .ReadFromJsonAsync<JsonElement>();

        Assert.Equal(
            400,
            problemDetails.GetProperty("status").GetInt32());

        Assert.Equal(
            "Validation failed.",
            problemDetails.GetProperty("title").GetString());

        var errors =
            problemDetails
                .GetProperty("errors");

        Assert.True(
            errors.TryGetProperty(
                "RefreshToken",
                out _));

        Assert.True(
            problemDetails.TryGetProperty(
                "traceId",
                out _));
    }

    [Fact]
    public async Task RefreshToken_WhenRefreshTokenIsEmpty_ShouldReturnBadRequest()
    {
        var refreshResponse =
            await _client.PostAsJsonAsync(
                "/api/auth/refresh-token",
                new
                {
                    refreshToken = string.Empty
                });

        Assert.Equal(
            HttpStatusCode.BadRequest,
            refreshResponse.StatusCode);

        var problemDetails =
            await refreshResponse.Content
                .ReadFromJsonAsync<JsonElement>();

        Assert.Equal(
            400,
            problemDetails.GetProperty("status").GetInt32());

        Assert.Equal(
            "Validation failed.",
            problemDetails.GetProperty("title").GetString());

        var errors =
            problemDetails
                .GetProperty("errors");

        Assert.True(
            errors.TryGetProperty(
                "RefreshToken",
                out _));

        Assert.True(
            problemDetails.TryGetProperty(
                "traceId",
                out _));
    }

    [Fact]
    public async Task RefreshToken_ShouldPersistRotationRelationship()
    {
        var email =
            $"refresh-persistence-{Guid.NewGuid():N}@example.com";

        var password = "Password123!";

        var registerResponse =
            await _client.PostAsJsonAsync(
                "/api/auth/register",
                new
                {
                    email,
                    password
                });

        Assert.Equal(
            HttpStatusCode.Created,
            registerResponse.StatusCode);

        var loginResponse =
            await _client.PostAsJsonAsync(
                "/api/auth/login",
                new
                {
                    email,
                    password
                });

        Assert.Equal(
            HttpStatusCode.OK,
            loginResponse.StatusCode);

        var loginBody =
            await loginResponse.Content
                .ReadFromJsonAsync<JsonElement>();

        var originalRefreshToken =
            loginBody
                .GetProperty("refreshToken")
                .GetString();

        Assert.False(
            string.IsNullOrWhiteSpace(originalRefreshToken));

        var firstRefreshResponse =
            await _client.PostAsJsonAsync(
                "/api/auth/refresh-token",
                new
                {
                    refreshToken = originalRefreshToken
                });

        Assert.Equal(
            HttpStatusCode.OK,
            firstRefreshResponse.StatusCode);

        var refreshBody =
            await firstRefreshResponse.Content
                .ReadFromJsonAsync<JsonElement>();

        var newRefreshToken =
            refreshBody
                .GetProperty("refreshToken")
                .GetString();

        Assert.False(
            string.IsNullOrWhiteSpace(newRefreshToken));

        var originalTokenHash =
            Convert.ToHexString(
                System.Security.Cryptography.SHA256.HashData(
                    System.Text.Encoding.UTF8.GetBytes(
                        originalRefreshToken!)))
            .ToLowerInvariant();

        var newTokenHash =
            Convert.ToHexString(
                System.Security.Cryptography.SHA256.HashData(
                    System.Text.Encoding.UTF8.GetBytes(
                        newRefreshToken!)))
            .ToLowerInvariant();

        await using var connection =
            new Npgsql.NpgsqlConnection(
                _postgresFixture.ConnectionString);

        await connection.OpenAsync();

        const string sql = """
        SELECT
            old_token.id,
            old_token.family_id,
            old_token.revoked_at,
            old_token.replaced_by_token_id,
            new_token.id,
            new_token.family_id,
            new_token.revoked_at
        FROM public.refresh_tokens old_token
        INNER JOIN public.refresh_tokens new_token
            ON new_token.token_hash = @newTokenHash
        WHERE old_token.token_hash = @oldTokenHash;
        """;

        await using var command =
            new Npgsql.NpgsqlCommand(
                sql,
                connection);

        command.Parameters.AddWithValue(
            "oldTokenHash",
            originalTokenHash);

        command.Parameters.AddWithValue(
            "newTokenHash",
            newTokenHash);

        await using var reader =
            await command.ExecuteReaderAsync();

        Assert.True(
            await reader.ReadAsync());

        var oldTokenId =
            reader.GetInt32(0);

        var oldFamilyId =
            reader.GetGuid(1);

        var revokedAt =
            reader.IsDBNull(2)
                ? (DateTime?)null
                : reader.GetDateTime(2);

        var replacedByTokenId =
            reader.IsDBNull(3)
                ? (int?)null
                : reader.GetInt32(3);

        var newTokenId =
            reader.GetInt32(4);

        var newFamilyId =
            reader.GetGuid(5);

        var newRevokedAt =
            reader.IsDBNull(6)
                ? (DateTime?)null
                : reader.GetDateTime(6);

        Assert.True(oldTokenId > 0);
        Assert.True(newTokenId > 0);

        Assert.NotNull(revokedAt);

        Assert.Equal(
            newTokenId,
            replacedByTokenId);

        Assert.Equal(
            oldFamilyId,
            newFamilyId);

        Assert.Null(newRevokedAt);
    }

    [Fact]
    public async Task RefreshToken_WhenReuseIsDetected_ShouldPersistFamilyRevocation()
    {
        var email =
            $"refresh-family-persistence-{Guid.NewGuid():N}@example.com";

        var password = "Password123!";

        var registerResponse =
            await _client.PostAsJsonAsync(
                "/api/auth/register",
                new
                {
                    email,
                    password
                });

        Assert.Equal(
            HttpStatusCode.Created,
            registerResponse.StatusCode);

        var loginResponse =
            await _client.PostAsJsonAsync(
                "/api/auth/login",
                new
                {
                    email,
                    password
                });

        Assert.Equal(
            HttpStatusCode.OK,
            loginResponse.StatusCode);

        var loginBody =
            await loginResponse.Content
                .ReadFromJsonAsync<JsonElement>();

        var originalRefreshToken =
            loginBody
                .GetProperty("refreshToken")
                .GetString();

        Assert.False(
            string.IsNullOrWhiteSpace(originalRefreshToken));

        var firstRefreshResponse =
            await _client.PostAsJsonAsync(
                "/api/auth/refresh-token",
                new
                {
                    refreshToken = originalRefreshToken
                });

        Assert.Equal(
            HttpStatusCode.OK,
            firstRefreshResponse.StatusCode);

        var refreshBody =
            await firstRefreshResponse.Content
                .ReadFromJsonAsync<JsonElement>();

        var rotatedRefreshToken =
            refreshBody
                .GetProperty("refreshToken")
                .GetString();

        Assert.False(
            string.IsNullOrWhiteSpace(rotatedRefreshToken));

        var originalTokenHash =
            Convert.ToHexString(
                System.Security.Cryptography.SHA256.HashData(
                    System.Text.Encoding.UTF8.GetBytes(
                        originalRefreshToken!)))
            .ToLowerInvariant();

        var rotatedTokenHash =
            Convert.ToHexString(
                System.Security.Cryptography.SHA256.HashData(
                    System.Text.Encoding.UTF8.GetBytes(
                        rotatedRefreshToken!)))
            .ToLowerInvariant();

        // Reuse the already-rotated token.
        var reuseResponse =
            await _client.PostAsJsonAsync(
                "/api/auth/refresh-token",
                new
                {
                    refreshToken = originalRefreshToken
                });

        Assert.Equal(
            HttpStatusCode.Unauthorized,
            reuseResponse.StatusCode);

        await using var connection =
            new Npgsql.NpgsqlConnection(
                _postgresFixture.ConnectionString);

        await connection.OpenAsync();

        const string sql = """
        SELECT
            family_id,
            COUNT(*) AS token_count,
            COUNT(*) FILTER (
                WHERE revoked_at IS NOT NULL
            ) AS revoked_count
        FROM public.refresh_tokens
        WHERE family_id = (
            SELECT family_id
            FROM public.refresh_tokens
            WHERE token_hash = @originalTokenHash
        )
        GROUP BY family_id;
        """;

        await using var command =
            new Npgsql.NpgsqlCommand(
                sql,
                connection);

        command.Parameters.AddWithValue(
            "originalTokenHash",
            originalTokenHash);

        await using var reader =
            await command.ExecuteReaderAsync();

        Assert.True(
            await reader.ReadAsync());

        var familyId =
            reader.GetGuid(0);

        var tokenCount =
            reader.GetInt32(1);

        var revokedCount =
            reader.GetInt32(2);

        Assert.True(
            tokenCount >= 2);

        Assert.Equal(
            tokenCount,
            revokedCount);
    }

    [Fact]
    public async Task RefreshToken_WhenOneSessionIsRevoked_ShouldNotAffectAnotherSession()
    {
        var email =
            $"refresh-session-{Guid.NewGuid():N}@example.com";

        var password = "Password123!";

        var registerResponse =
            await _client.PostAsJsonAsync(
                "/api/auth/register",
                new
                {
                    email,
                    password
                });

        Assert.Equal(
            HttpStatusCode.Created,
            registerResponse.StatusCode);

        // Login from session/device A.
        var firstLoginResponse =
            await _client.PostAsJsonAsync(
                "/api/auth/login",
                new
                {
                    email,
                    password
                });

        Assert.Equal(
            HttpStatusCode.OK,
            firstLoginResponse.StatusCode);

        var firstLoginBody =
            await firstLoginResponse.Content
                .ReadFromJsonAsync<JsonElement>();

        var firstAccessToken =
            firstLoginBody
                .GetProperty("accessToken")
                .GetString();

        var firstRefreshToken =
            firstLoginBody
                .GetProperty("refreshToken")
                .GetString();

        Assert.False(
            string.IsNullOrWhiteSpace(firstAccessToken));

        Assert.False(
            string.IsNullOrWhiteSpace(firstRefreshToken));

        // Login from session/device B.
        var secondLoginResponse =
            await _client.PostAsJsonAsync(
                "/api/auth/login",
                new
                {
                    email,
                    password
                });

        Assert.Equal(
            HttpStatusCode.OK,
            secondLoginResponse.StatusCode);

        var secondLoginBody =
            await secondLoginResponse.Content
                .ReadFromJsonAsync<JsonElement>();

        var secondRefreshToken =
            secondLoginBody
                .GetProperty("refreshToken")
                .GetString();

        Assert.False(
            string.IsNullOrWhiteSpace(secondRefreshToken));

        Assert.NotEqual(
            firstRefreshToken,
            secondRefreshToken);

        _client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue(
                "Bearer",
                firstAccessToken);

        // Logout session A.
        var logoutResponse =
            await _client.PostAsJsonAsync(
                "/api/auth/logout",
                new
                {
                    refreshToken = firstRefreshToken
                });

        Assert.Equal(
            HttpStatusCode.NoContent,
            logoutResponse.StatusCode);

        // Session A must no longer work.
        var firstSessionRefreshResponse =
            await _client.PostAsJsonAsync(
                "/api/auth/refresh-token",
                new
                {
                    refreshToken = firstRefreshToken
                });

        Assert.Equal(
            HttpStatusCode.Unauthorized,
            firstSessionRefreshResponse.StatusCode);

        // Session B must remain valid.
        var secondSessionRefreshResponse =
            await _client.PostAsJsonAsync(
                "/api/auth/refresh-token",
                new
                {
                    refreshToken = secondRefreshToken
                });

        Assert.Equal(
            HttpStatusCode.OK,
            secondSessionRefreshResponse.StatusCode);

        var secondRefreshBody =
            await secondSessionRefreshResponse.Content
                .ReadFromJsonAsync<JsonElement>();

        Assert.False(
            string.IsNullOrWhiteSpace(
                secondRefreshBody
                    .GetProperty("accessToken")
                    .GetString()));

        Assert.False(
            string.IsNullOrWhiteSpace(
                secondRefreshBody
                    .GetProperty("refreshToken")
                    .GetString()));
    }

    [Fact]
    public async Task Login_Twice_ShouldCreateSeparateRefreshTokenFamilies()
    {
        var email =
            $"refresh-families-{Guid.NewGuid():N}@example.com";

        var password = "Password123!";

        var registerResponse =
            await _client.PostAsJsonAsync(
                "/api/auth/register",
                new
                {
                    email,
                    password
                });

        Assert.Equal(
            HttpStatusCode.Created,
            registerResponse.StatusCode);

        var firstLoginResponse =
            await _client.PostAsJsonAsync(
                "/api/auth/login",
                new
                {
                    email,
                    password
                });

        Assert.Equal(
            HttpStatusCode.OK,
            firstLoginResponse.StatusCode);

        var secondLoginResponse =
            await _client.PostAsJsonAsync(
                "/api/auth/login",
                new
                {
                    email,
                    password
                });

        Assert.Equal(
            HttpStatusCode.OK,
            secondLoginResponse.StatusCode);

        await using var connection =
            new Npgsql.NpgsqlConnection(
                _postgresFixture.ConnectionString);

        await connection.OpenAsync();

        const string sql = """
        SELECT DISTINCT family_id
        FROM public.refresh_tokens
        WHERE user_id = (
            SELECT id
            FROM public.users
            WHERE email = @email
        );
        """;

        await using var command =
            new Npgsql.NpgsqlCommand(
                sql,
                connection);

        command.Parameters.AddWithValue(
            "email",
            email);

        await using var reader =
            await command.ExecuteReaderAsync();

        var familyIds = new List<Guid>();

        while (await reader.ReadAsync())
        {
            familyIds.Add(
                reader.GetGuid(0));
        }

        Assert.Equal(
            2,
            familyIds.Count);

        Assert.NotEqual(
            familyIds[0],
            familyIds[1]);
    }

    [Fact]
    public async Task Login_ShouldPersistSha256HashOfRefreshToken()
    {
        var email =
            $"refresh-hash-{Guid.NewGuid():N}@example.com";

        var password = "Password123!";

        var registerResponse =
            await _client.PostAsJsonAsync(
                "/api/auth/register",
                new
                {
                    email,
                    password
                });

        Assert.Equal(
            HttpStatusCode.Created,
            registerResponse.StatusCode);

        var loginResponse =
            await _client.PostAsJsonAsync(
                "/api/auth/login",
                new
                {
                    email,
                    password
                });

        Assert.Equal(
            HttpStatusCode.OK,
            loginResponse.StatusCode);

        var loginBody =
            await loginResponse.Content
                .ReadFromJsonAsync<JsonElement>();

        var refreshToken =
            loginBody
                .GetProperty("refreshToken")
                .GetString();

        Assert.False(
            string.IsNullOrWhiteSpace(refreshToken));

        var expectedHash =
            Convert.ToHexString(
                System.Security.Cryptography.SHA256.HashData(
                    System.Text.Encoding.UTF8.GetBytes(
                        refreshToken!)))
            .ToLowerInvariant();

        await using var connection =
            new Npgsql.NpgsqlConnection(
                _postgresFixture.ConnectionString);

        await connection.OpenAsync();

        const string sql = """
        SELECT token_hash
        FROM public.refresh_tokens
        WHERE user_id = (
            SELECT id
            FROM public.users
            WHERE email = @email
        );
        """;

        await using var command =
            new Npgsql.NpgsqlCommand(
                sql,
                connection);

        command.Parameters.AddWithValue(
            "email",
            email);

        var storedHash =
            await command.ExecuteScalarAsync();

        Assert.NotNull(storedHash);

        Assert.Equal(
            expectedHash,
            storedHash.ToString());

        Assert.NotEqual(
            refreshToken,
            storedHash.ToString());
    }

    [Fact]
    public async Task RefreshToken_ConcurrentRequests_ShouldAllowOnlyOneSuccessfulRotation()
    {
        var email =
            $"refresh-concurrent-{Guid.NewGuid():N}@example.com";

        var password = "Password123!";

        var registerResponse =
            await _client.PostAsJsonAsync(
                "/api/auth/register",
                new
                {
                    email,
                    password
                });

        Assert.Equal(
            HttpStatusCode.Created,
            registerResponse.StatusCode);

        var loginResponse =
            await _client.PostAsJsonAsync(
                "/api/auth/login",
                new
                {
                    email,
                    password
                });

        Assert.Equal(
            HttpStatusCode.OK,
            loginResponse.StatusCode);

        var loginBody =
            await loginResponse.Content
                .ReadFromJsonAsync<JsonElement>();

        var refreshToken =
            loginBody
                .GetProperty("refreshToken")
                .GetString();

        Assert.False(
            string.IsNullOrWhiteSpace(refreshToken));

        var requestBody = new
        {
            refreshToken
        };

        var request1 = _client.PostAsJsonAsync(
            "/api/auth/refresh-token",
            requestBody);

        var request2 = _client.PostAsJsonAsync(
            "/api/auth/refresh-token",
            requestBody);

        var responses = await Task.WhenAll(
            request1,
            request2);

        var successCount =
            responses.Count(response =>
                response.StatusCode == HttpStatusCode.OK);

        var unauthorizedCount =
            responses.Count(response =>
                response.StatusCode == HttpStatusCode.Unauthorized);

        Assert.Equal(1, successCount);
        Assert.Equal(1, unauthorizedCount);
    }

    [Fact]
    public async Task RefreshToken_AfterRotation_ShouldAllowNewTokenToRotate()
    {
        var email =
            $"refresh-chain-{Guid.NewGuid():N}@example.com";

        var password = "Password123!";

        var registerResponse =
            await _client.PostAsJsonAsync(
                "/api/auth/register",
                new
                {
                    email,
                    password
                });

        Assert.Equal(
            HttpStatusCode.Created,
            registerResponse.StatusCode);

        var loginResponse =
            await _client.PostAsJsonAsync(
                "/api/auth/login",
                new
                {
                    email,
                    password
                });

        Assert.Equal(
            HttpStatusCode.OK,
            loginResponse.StatusCode);

        var loginBody =
            await loginResponse.Content
                .ReadFromJsonAsync<JsonElement>();

        var refreshTokenA =
            loginBody
                .GetProperty("refreshToken")
                .GetString();

        Assert.False(
            string.IsNullOrWhiteSpace(refreshTokenA));

        var firstRefreshResponse =
            await _client.PostAsJsonAsync(
                "/api/auth/refresh-token",
                new
                {
                    refreshToken = refreshTokenA
                });

        Assert.Equal(
            HttpStatusCode.OK,
            firstRefreshResponse.StatusCode);

        var firstRefreshBody =
            await firstRefreshResponse.Content
                .ReadFromJsonAsync<JsonElement>();

        var refreshTokenB =
            firstRefreshBody
                .GetProperty("refreshToken")
                .GetString();

        Assert.False(
            string.IsNullOrWhiteSpace(refreshTokenB));

        Assert.NotEqual(
            refreshTokenA,
            refreshTokenB);

        var secondRefreshResponse =
            await _client.PostAsJsonAsync(
                "/api/auth/refresh-token",
                new
                {
                    refreshToken = refreshTokenB
                });

        Assert.Equal(
            HttpStatusCode.OK,
            secondRefreshResponse.StatusCode);

        var secondRefreshBody =
            await secondRefreshResponse.Content
                .ReadFromJsonAsync<JsonElement>();

        var refreshTokenC =
            secondRefreshBody
                .GetProperty("refreshToken")
                .GetString();

        Assert.False(
            string.IsNullOrWhiteSpace(refreshTokenC));

        Assert.NotEqual(
            refreshTokenB,
            refreshTokenC);

        Assert.NotEqual(
            refreshTokenA,
            refreshTokenC);
    }
}