using Authentication.IntegrationTests.Infrastructure;
using Microsoft.IdentityModel.Tokens;
using Npgsql;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Http.Json;
using System.Text.Json;

namespace Authentication.IntegrationTests.Auth;

public sealed class LoginTests
    : IClassFixture<PostgreSqlFixture>,
      IAsyncLifetime
{
    private readonly PostgreSqlFixture _postgresFixture;
    private AuthenticationWebApplicationFactory _factory = null!;
    private HttpClient _client = null!;

    public LoginTests(
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
    public async Task Login_WithValidCredentials_ShouldReturnTokens()
    {
        var email =
            $"login-{Guid.NewGuid():N}@example.com";

        var password = "Password123!";

        var registerRequest = new
        {
            email,
            password
        };

        var registerResponse =
            await _client.PostAsJsonAsync(
                "/api/auth/register",
                registerRequest);

        Assert.Equal(
            HttpStatusCode.Created,
            registerResponse.StatusCode);

        var loginResponse =
            await _client.PostAsJsonAsync(
                "/api/auth/login",
                registerRequest);

        Assert.Equal(
            HttpStatusCode.OK,
            loginResponse.StatusCode);

        var loginBody =
            await loginResponse.Content
                .ReadFromJsonAsync<JsonElement>();

        Assert.True(
            loginBody.TryGetProperty(
                "accessToken",
                out var accessToken));

        Assert.False(
            string.IsNullOrWhiteSpace(
                accessToken.GetString()));

        Assert.True(
            loginBody.TryGetProperty(
                "refreshToken",
                out var refreshToken));

        Assert.False(
            string.IsNullOrWhiteSpace(
                refreshToken.GetString()));

        Assert.True(
            loginBody.TryGetProperty(
                "tokenType",
                out var tokenType));

        Assert.Equal(
            "Bearer",
            tokenType.GetString());

        Assert.True(
            loginBody.TryGetProperty(
                "expiresAt",
                out var expiresAt));

        Assert.True(
            expiresAt.GetDateTime() > DateTime.UtcNow);
    }

    [Fact]
    public async Task Login_ShouldPersistRefreshTokenHash()
    {
        var email =
            $"refresh-{Guid.NewGuid():N}@example.com";

        var password = "Password123!";

        var request = new
        {
            email,
            password
        };

        var registerResponse =
            await _client.PostAsJsonAsync(
                "/api/auth/register",
                request);

        Assert.Equal(
            HttpStatusCode.Created,
            registerResponse.StatusCode);

        var loginResponse =
            await _client.PostAsJsonAsync(
                "/api/auth/login",
                request);

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

        await using var connection =
            new NpgsqlConnection(
                _postgresFixture.ConnectionString);

        await connection.OpenAsync();

        const string sql = """
            SELECT COUNT(*)
            FROM public.refresh_tokens
            WHERE user_id = (
                SELECT id
                FROM public.users
                WHERE email = @email
            );
            """;

        await using var command =
            new NpgsqlCommand(sql, connection);

        command.Parameters.AddWithValue(
            "email",
            email);

        var tokenCount =
            Convert.ToInt32(
                await command.ExecuteScalarAsync());

        Assert.Equal(
            1,
            tokenCount);
    }

    [Fact]
    public async Task Login_WithUnknownEmail_ShouldReturnUnauthorized()
    {
        var request = new
        {
            email = $"unknown-{Guid.NewGuid():N}@example.com",
            password = "Password123!"
        };

        var response =
            await _client.PostAsJsonAsync(
                "/api/auth/login",
                request);

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

        Assert.False(
            string.IsNullOrWhiteSpace(
                problemDetails.GetProperty("detail").GetString()));
    }

    [Fact]
    public async Task Login_WithWrongPassword_ShouldReturnUnauthorized()
    {
        var email =
            $"wrong-password-{Guid.NewGuid():N}@example.com";

        var correctPassword = "Password123!";

        var registerRequest = new
        {
            email,
            password = correctPassword
        };

        var registerResponse =
            await _client.PostAsJsonAsync(
                "/api/auth/register",
                registerRequest);

        Assert.Equal(
            HttpStatusCode.Created,
            registerResponse.StatusCode);

        var loginRequest = new
        {
            email,
            password = "WrongPassword123!"
        };

        var response =
            await _client.PostAsJsonAsync(
                "/api/auth/login",
                loginRequest);

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
    public async Task Login_WithInvalidEmail_ShouldReturnBadRequest()
    {
        var request = new
        {
            email = "invalid-email",
            password = "Password123!"
        };

        var response =
            await _client.PostAsJsonAsync(
                "/api/auth/login",
                request);

        Assert.Equal(
            HttpStatusCode.BadRequest,
            response.StatusCode);

        var problemDetails =
            await response.Content
                .ReadFromJsonAsync<JsonElement>();

        Assert.Equal(
            400,
            problemDetails.GetProperty("status").GetInt32());

        Assert.Equal(
            "Validation failed.",
            problemDetails.GetProperty("title").GetString());

        var errors =
            problemDetails.GetProperty("errors");

        Assert.True(
            errors.TryGetProperty(
                "Email",
                out var emailErrors));

        Assert.NotEqual(
            0,
            emailErrors.GetArrayLength());
    }

    [Fact]
    public async Task Login_WithoutPassword_ShouldReturnBadRequest()
    {
        var request = new
        {
            email = $"missing-password-{Guid.NewGuid():N}@example.com",
            password = ""
        };

        var response =
            await _client.PostAsJsonAsync(
                "/api/auth/login",
                request);

        Assert.Equal(
            HttpStatusCode.BadRequest,
            response.StatusCode);

        var problemDetails =
            await response.Content
                .ReadFromJsonAsync<JsonElement>();

        Assert.Equal(
            400,
            problemDetails.GetProperty("status").GetInt32());

        var errors =
            problemDetails.GetProperty("errors");

        Assert.True(
            errors.TryGetProperty(
                "Password",
                out var passwordErrors));

        Assert.NotEqual(
            0,
            passwordErrors.GetArrayLength());
    }

    [Fact]
    public async Task Login_WithWrongPassword_ShouldNotCreateRefreshToken()
    {
        var email =
            $"no-refresh-{Guid.NewGuid():N}@example.com";

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

        await using var connection =
            new NpgsqlConnection(
                _postgresFixture.ConnectionString);

        await connection.OpenAsync();

        const string sql = """
        SELECT COUNT(*)
        FROM public.refresh_tokens rt
        INNER JOIN public.users u
            ON u.id = rt.user_id
        WHERE u.email = @email;
        """;

        await using var command =
            new NpgsqlCommand(sql, connection);

        command.Parameters.AddWithValue(
            "email",
            email);

        var tokenCount =
            Convert.ToInt32(
                await command.ExecuteScalarAsync());

        Assert.Equal(
            0,
            tokenCount);
    }

    [Fact]
    public async Task Login_ShouldReturnCryptographicallyValidJwt()
    {
        var email =
            $"jwt-{Guid.NewGuid():N}@example.com";

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

        Assert.False(
            string.IsNullOrWhiteSpace(accessToken));

        var validationParameters =
            new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidIssuer = "Authentication.Api",

                ValidateAudience = true,
                ValidAudience = "Authentication.Client",

                ValidateIssuerSigningKey = true,
                IssuerSigningKey =
                    new SymmetricSecurityKey(
                        Convert.FromBase64String(
                            _factory.JwtKey)),

                ValidateLifetime = true,
                RequireExpirationTime = true,
                RequireSignedTokens = true,

                ClockSkew = TimeSpan.Zero
            };

        var handler =
            new JwtSecurityTokenHandler();

        var principal =
            handler.ValidateToken(
                accessToken,
                validationParameters,
                out var validatedToken);

        Assert.NotNull(validatedToken);

        Assert.Equal(
            email,
            principal.Identity?.Name);

        Assert.True(
            principal.IsInRole("user"));
    }

    [Fact]
    public async Task Login_ShouldReturnJwtWithExpectedClaims()
    {
        var email =
            $"claims-{Guid.NewGuid():N}@example.com";

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

        Assert.False(
            string.IsNullOrWhiteSpace(accessToken));

        var handler =
            new JwtSecurityTokenHandler();

        var token =
            handler.ReadJwtToken(accessToken);

        Assert.Equal(
            "Authentication.Api",
            token.Issuer);

        Assert.Contains(
            "Authentication.Client",
            token.Audiences);

        var subject =
            token.Claims
                .Single(c =>
                    c.Type == JwtRegisteredClaimNames.Sub)
                .Value;

        var jti =
            token.Claims
                .Single(c =>
                    c.Type == JwtRegisteredClaimNames.Jti)
                .Value;

        var issuedAt =
            token.Claims
                .Single(c =>
                    c.Type == JwtRegisteredClaimNames.Iat)
                .Value;

        var name =
            token.Claims
                .Single(c =>
                    c.Type == "unique_name")
                .Value;

        var role =
            token.Claims
                .Single(c =>
                    c.Type == "role")
                .Value;

        Assert.True(
            int.TryParse(
                subject,
                out var userId));

        Assert.True(
            userId > 0);

        Assert.True(
            Guid.TryParse(
                jti,
                out _));

        Assert.True(
            long.TryParse(
                issuedAt,
                out _));

        Assert.Equal(
            email,
            name);

        Assert.Equal(
            "user",
            role);

        Assert.True(
            token.ValidTo > DateTime.UtcNow);
    }
}