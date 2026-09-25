using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Authentication.IntegrationTests.Infrastructure;

namespace Authentication.IntegrationTests.Security;

public sealed class AuthenticationErrorTests
    : IClassFixture<PostgreSqlFixture>,
      IAsyncLifetime
{
    private readonly PostgreSqlFixture _postgresFixture;

    private AuthenticationWebApplicationFactory _factory = null!;
    private HttpClient _client = null!;

    public AuthenticationErrorTests(
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
    public async Task Login_WithUnknownEmail_ShouldReturnGenericUnauthorizedResponse()
    {
        var response =
            await _client.PostAsJsonAsync(
                "/api/auth/login",
                new
                {
                    email = $"unknown-{Guid.NewGuid():N}@example.com",
                    password = "WrongPassword123!"
                });

        Assert.Equal(
            HttpStatusCode.Unauthorized,
            response.StatusCode);

        var problemDetails =
            await response.Content
                .ReadFromJsonAsync<JsonElement>();

        Assert.Equal(
            401,
            problemDetails.GetProperty("status").GetInt32());

        Assert.Equal(
            "Unauthorized",
            problemDetails.GetProperty("title").GetString());

        Assert.Equal(
            "Invalid email or password.",
            problemDetails.GetProperty("detail").GetString());

        Assert.True(
            problemDetails.TryGetProperty(
                "traceId",
                out _));
    }

    [Fact]
    public async Task Login_WithInvalidPassword_ShouldReturnSameUnauthorizedResponse()
    {
        var email =
            $"login-security-{Guid.NewGuid():N}@example.com";

        var password = "CorrectPassword123!";

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

        var response =
            await _client.PostAsJsonAsync(
                "/api/auth/login",
                new
                {
                    email,
                    password = "WrongPassword123!"
                });

        Assert.Equal(
            HttpStatusCode.Unauthorized,
            response.StatusCode);

        var problemDetails =
            await response.Content
                .ReadFromJsonAsync<JsonElement>();

        Assert.Equal(
            401,
            problemDetails.GetProperty("status").GetInt32());

        Assert.Equal(
            "Unauthorized",
            problemDetails.GetProperty("title").GetString());

        Assert.Equal(
            "Invalid email or password.",
            problemDetails.GetProperty("detail").GetString());

        Assert.True(
            problemDetails.TryGetProperty(
                "traceId",
                out _));
    }

    [Fact]
    public async Task RefreshToken_WithInvalidToken_ShouldReturnGenericUnauthorizedResponse()
    {
        var response =
            await _client.PostAsJsonAsync(
                "/api/auth/refresh-token",
                new
                {
                    refreshToken =
                        $"invalid-refresh-token-{Guid.NewGuid():N}"
                });

        Assert.Equal(
            HttpStatusCode.Unauthorized,
            response.StatusCode);

        var problemDetails =
            await response.Content
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
}