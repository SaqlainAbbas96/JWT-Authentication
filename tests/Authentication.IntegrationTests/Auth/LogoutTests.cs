using Authentication.IntegrationTests.Infrastructure;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;

namespace Authentication.IntegrationTests.Auth;

public sealed class LogoutTests
    : IClassFixture<PostgreSqlFixture>,
      IAsyncLifetime
{
    private readonly PostgreSqlFixture _postgresFixture;

    private AuthenticationWebApplicationFactory _factory = null!;
    private HttpClient _client = null!;

    public LogoutTests(
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
    public async Task Logout_WithValidRefreshToken_ShouldReturnNoContent()
    {
        var email =
            $"logout-{Guid.NewGuid():N}@example.com";

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

        var accessToken =
            loginBody
                .GetProperty("accessToken")
                .GetString();

        var refreshToken =
            loginBody
                .GetProperty("refreshToken")
                .GetString();

        Assert.False(
            string.IsNullOrWhiteSpace(accessToken));

        Assert.False(
            string.IsNullOrWhiteSpace(refreshToken));

        SetBearerToken(
            _client,
            accessToken!);

        var logoutResponse =
            await _client.PostAsJsonAsync(
                "/api/auth/logout",
                new
                {
                    refreshToken
                });

        Assert.Equal(
            HttpStatusCode.NoContent,
            logoutResponse.StatusCode);

        Assert.Equal(
            0,
            logoutResponse.Content.Headers.ContentLength ?? 0);
    }

    [Fact]
    public async Task Logout_ShouldInvalidateRefreshToken()
    {
        var email =
            $"logout-invalidate-{Guid.NewGuid():N}@example.com";

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

        var accessToken =
            loginBody
                .GetProperty("accessToken")
                .GetString();

        var refreshToken =
            loginBody
                .GetProperty("refreshToken")
                .GetString();

        Assert.False(
            string.IsNullOrWhiteSpace(accessToken));

        Assert.False(
            string.IsNullOrWhiteSpace(refreshToken));

        SetBearerToken(
           _client,
           accessToken!);

        var logoutResponse =
            await _client.PostAsJsonAsync(
                "/api/auth/logout",
                new
                {
                    refreshToken
                });

        Assert.Equal(
            HttpStatusCode.NoContent,
            logoutResponse.StatusCode);

        var refreshResponse =
            await _client.PostAsJsonAsync(
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
    public async Task Logout_WithUnknownRefreshToken_ShouldReturnNoContent()
    {
        var email =
            $"logout-unknown-{Guid.NewGuid():N}@example.com";

        var password = "Password123!";

        await _client.PostAsJsonAsync(
            "/api/auth/register",
            new
            {
                email,
                password
            });

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

        var accessToken =
            loginBody
                .GetProperty("accessToken")
                .GetString();

        Assert.False(
            string.IsNullOrWhiteSpace(accessToken));

        _client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue(
                "Bearer",
                accessToken);

        var refreshToken =
            "unknown-refresh-token-that-does-not-exist";

        var logoutResponse =
            await _client.PostAsJsonAsync(
                "/api/auth/logout",
                new
                {
                    refreshToken
                });

        Assert.Equal(
            HttpStatusCode.NoContent,
            logoutResponse.StatusCode);

        Assert.Equal(
            0,
            logoutResponse.Content.Headers.ContentLength ?? 0);
    }

    [Fact]
    public async Task Logout_WhenRefreshTokenIsMissing_ShouldReturnBadRequest()
    {
        var email =
            $"logout-missing-{Guid.NewGuid():N}@example.com";

        var password = "Password123!";

        await _client.PostAsJsonAsync(
            "/api/auth/register",
            new
            {
                email,
                password
            });

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

        var accessToken =
            loginBody
                .GetProperty("accessToken")
                .GetString();

        Assert.False(
            string.IsNullOrWhiteSpace(accessToken));

        _client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue(
                "Bearer",
                accessToken);

        var logoutResponse =
            await _client.PostAsJsonAsync(
                "/api/auth/logout",
                new
                {
                });

        Assert.Equal(
            HttpStatusCode.BadRequest,
            logoutResponse.StatusCode);

        var problemDetails =
            await logoutResponse.Content
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
    public async Task Logout_WhenRefreshTokenIsEmpty_ShouldReturnBadRequest()
    {
        var email =
            $"logout-empty-{Guid.NewGuid():N}@example.com";

        var password = "Password123!";

        await _client.PostAsJsonAsync(
            "/api/auth/register",
            new
            {
                email,
                password
            });

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

        var accessToken =
            loginBody
                .GetProperty("accessToken")
                .GetString();

        Assert.False(
            string.IsNullOrWhiteSpace(accessToken));

        _client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue(
                "Bearer",
                accessToken);

        var logoutResponse =
            await _client.PostAsJsonAsync(
                "/api/auth/logout",
                new
                {
                    refreshToken = string.Empty
                });

        Assert.Equal(
            HttpStatusCode.BadRequest,
            logoutResponse.StatusCode);

        var problemDetails =
            await logoutResponse.Content
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
    public async Task Logout_ShouldRevokeRefreshTokenFamily()
    {
        var email =
            $"logout-revoke-{Guid.NewGuid():N}@example.com";

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

        var accessToken =
            loginBody
                .GetProperty("accessToken")
                .GetString();

        var refreshToken =
            loginBody
                .GetProperty("refreshToken")
                .GetString();

        Assert.False(
            string.IsNullOrWhiteSpace(accessToken));

        Assert.False(
            string.IsNullOrWhiteSpace(refreshToken));

        SetBearerToken(
           _client,
           accessToken!);

        var logoutResponse =
            await _client.PostAsJsonAsync(
                "/api/auth/logout",
                new
                {
                    refreshToken
                });

        Assert.Equal(
            HttpStatusCode.NoContent,
            logoutResponse.StatusCode);

        var refreshResponse =
            await _client.PostAsJsonAsync(
                "/api/auth/refresh-token",
                new
                {
                    refreshToken
                });

        Assert.Equal(
            HttpStatusCode.Unauthorized,
            refreshResponse.StatusCode);
    }

    [Fact]
    public async Task Logout_ShouldPersistRevokedAt()
    {
        var email =
            $"logout-persist-{Guid.NewGuid():N}@example.com";

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

        var accessToken =
            loginBody
                .GetProperty("accessToken")
                .GetString();

        var refreshToken =
            loginBody
                .GetProperty("refreshToken")
                .GetString();

        Assert.False(
            string.IsNullOrWhiteSpace(accessToken));

        Assert.False(
            string.IsNullOrWhiteSpace(refreshToken));

        SetBearerToken(
           _client,
           accessToken!);

        var logoutResponse =
            await _client.PostAsJsonAsync(
                "/api/auth/logout",
                new
                {
                    refreshToken
                });

        Assert.Equal(
            HttpStatusCode.NoContent,
            logoutResponse.StatusCode);

        var tokenHash =
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
        SELECT revoked_at
        FROM public.refresh_tokens
        WHERE token_hash = @tokenHash;
        """;

        await using var command =
            new Npgsql.NpgsqlCommand(
                sql,
                connection);

        command.Parameters.AddWithValue(
            "tokenHash",
            tokenHash);

        var revokedAt =
            await command.ExecuteScalarAsync();

        Assert.NotNull(revokedAt);
        Assert.NotEqual(
            DBNull.Value,
            revokedAt);

        Assert.True(
            revokedAt is DateTime);
    }

    [Fact]
    public async Task Logout_WhenCalledTwiceWithSameRefreshToken_ShouldRemainSuccessful()
    {
        var email =
            $"logout-idempotent-{Guid.NewGuid():N}@example.com";

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

        var accessToken =
            loginBody
                .GetProperty("accessToken")
                .GetString();

        var refreshToken =
            loginBody
                .GetProperty("refreshToken")
                .GetString();

        Assert.False(
            string.IsNullOrWhiteSpace(accessToken));

        Assert.False(
            string.IsNullOrWhiteSpace(refreshToken));

        SetBearerToken(
           _client,
           accessToken!);

        var firstLogoutResponse =
            await _client.PostAsJsonAsync(
                "/api/auth/logout",
                new
                {
                    refreshToken
                });

        Assert.Equal(
            HttpStatusCode.NoContent,
            firstLogoutResponse.StatusCode);

        var secondLogoutResponse =
            await _client.PostAsJsonAsync(
                "/api/auth/logout",
                new
                {
                    refreshToken
                });

        Assert.Equal(
            HttpStatusCode.NoContent,
            secondLogoutResponse.StatusCode);
    }

    private static void SetBearerToken(
        HttpClient client,
        string accessToken)
    {
        client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue(
                "Bearer",
                accessToken);
    }
}