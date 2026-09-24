using Authentication.IntegrationTests.Infrastructure;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;

namespace Authentication.IntegrationTests.Security;

public sealed class EndpointAuthorizationTests
    : IClassFixture<PostgreSqlFixture>
{
    private readonly PostgreSqlFixture _fixture;

    public EndpointAuthorizationTests(
        PostgreSqlFixture fixture)
    {
        _fixture = fixture;
    }

    [Fact]
    public async Task ProtectedEndpoint_ShouldReturnUnauthorized_WhenAccessTokenIsMissing()
    {
        await using var factory =
            new AuthenticationWebApplicationFactory(
                _fixture.ConnectionString);

        using var client = factory.CreateClient();

        using var response =
            await client.PostAsJsonAsync(
                "/api/auth/logout",
                new
                {
                    refreshToken = "invalid-token"
                });

        Assert.Equal(
            HttpStatusCode.Unauthorized,
            response.StatusCode);
    }

    [Fact]
    public async Task Register_ShouldAllowAnonymousAccess()
    {
        await using var factory =
            new AuthenticationWebApplicationFactory(
                _fixture.ConnectionString);

        using var client = factory.CreateClient();

        using var response =
            await client.PostAsJsonAsync(
                "/api/auth/register",
                new
                {
                    email =
                        $"anonymous-{Guid.NewGuid()}@example.com",
                    password = "Password123!"
                });

        Assert.NotEqual(
            HttpStatusCode.Unauthorized,
            response.StatusCode);
    }

    [Fact]
    public async Task Login_ShouldAllowAnonymousAccess()
    {
        await using var factory =
            new AuthenticationWebApplicationFactory(
                _fixture.ConnectionString);

        using var client = factory.CreateClient();

        using var response =
            await client.PostAsJsonAsync(
                "/api/auth/login",
                new
                {
                    email =
                        $"anonymous-login-{Guid.NewGuid()}@example.com",
                    password = "Password123!"
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
    }

    [Fact]
    public async Task RefreshToken_ShouldAllowAnonymousAccess()
    {
        await using var factory =
            new AuthenticationWebApplicationFactory(
                _fixture.ConnectionString);

        using var client = factory.CreateClient();

        using var response =
            await client.PostAsJsonAsync(
                "/api/auth/refresh-token",
                new
                {
                    refreshToken =
                        $"invalid-{Guid.NewGuid()}"
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
    }

    [Fact]
    public async Task Logout_ShouldAllowAuthenticatedRequest()
    {
        await using var factory =
            new AuthenticationWebApplicationFactory(
                _fixture.ConnectionString);

        using var client = factory.CreateClient();

        var email =
            $"logout-auth-{Guid.NewGuid()}@example.com";

        var registerResponse =
            await client.PostAsJsonAsync(
                "/api/auth/register",
                new
                {
                    email,
                    password = "Password123!"
                });

        registerResponse.EnsureSuccessStatusCode();

        var loginResponse =
            await client.PostAsJsonAsync(
                "/api/auth/login",
                new
                {
                    email,
                    password = "Password123!"
                });

        loginResponse.EnsureSuccessStatusCode();

        var login =
            await loginResponse.Content
                .ReadFromJsonAsync<LoginResponse>();

        Assert.NotNull(login);

        client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue(
                "Bearer",
                login!.AccessToken);

        using var logoutResponse =
            await client.PostAsJsonAsync(
                "/api/auth/logout",
                new
                {
                    refreshToken =
                        login.RefreshToken
                });

        Assert.Equal(
            HttpStatusCode.NoContent,
            logoutResponse.StatusCode);
    }

    private sealed class LoginResponse
    {
        public string AccessToken { get; init; } = string.Empty;

        public string RefreshToken { get; init; } = string.Empty;
    }
}