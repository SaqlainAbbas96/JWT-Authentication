using Authentication.IntegrationTests.Infrastructure;
using Npgsql;
using System.Net;
using System.Net.Http.Json;
using System.Text.Json;

namespace Authentication.IntegrationTests.Auth;

public sealed class RegistrationTests
    : IClassFixture<PostgreSqlFixture>,
      IAsyncLifetime
{
    private readonly PostgreSqlFixture _postgresFixture;
    private AuthenticationWebApplicationFactory _factory = null!;
    private HttpClient _client = null!;

    public RegistrationTests(
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
    public async Task Register_WithValidRequest_ShouldCreateUserAndAssignDefaultRole()
    {
        var email =
            $"integration-{Guid.NewGuid():N}@example.com";

        var request = new
        {
            email,
            password = "Password123!"
        };

        var response = await _client.PostAsJsonAsync(
            "/api/auth/register",
            request);

        Assert.Equal(
            HttpStatusCode.Created,
            response.StatusCode);

        var responseBody =
            await response.Content.ReadAsStringAsync();

        using var json =
            JsonDocument.Parse(responseBody);

        Assert.True(
            json.RootElement.TryGetProperty(
                "userId",
                out var userIdProperty));

        var userId =
            userIdProperty.GetInt32();

        Assert.True(userId > 0);

        Assert.Equal(
            $"/api/users/{userId}",
            response.Headers.Location?.ToString());

        await using var connection =
            new NpgsqlConnection(
                _postgresFixture.ConnectionString);

        await connection.OpenAsync();

        const string userSql = """
            SELECT COUNT(*)
            FROM public.users
            WHERE id = @userId
              AND email = @email;
            """;

        await using var userCommand =
            new NpgsqlCommand(
                userSql,
                connection);

        userCommand.Parameters.AddWithValue(
            "userId",
            userId);

        userCommand.Parameters.AddWithValue(
            "email",
            email);

        var userCount =
            Convert.ToInt32(
                await userCommand.ExecuteScalarAsync());

        Assert.Equal(
            1,
            userCount);

        const string roleSql = """
            SELECT r.role_name
            FROM public.user_roles ur
            INNER JOIN public.roles r
                ON r.id = ur.role_id
            WHERE ur.user_id = @userId;
            """;

        await using var roleCommand =
            new NpgsqlCommand(
                roleSql,
                connection);

        roleCommand.Parameters.AddWithValue(
            "userId",
            userId);

        var roleName =
            await roleCommand.ExecuteScalarAsync();

        Assert.Equal(
            "user",
            roleName?.ToString());
    }

    [Fact]
    public async Task Database_ShouldContainDefaultRole()
    {
        await using var connection =
            new NpgsqlConnection(
                _postgresFixture.ConnectionString);

        await connection.OpenAsync();

        const string sql = """
            SELECT role_name
            FROM public.roles
            ORDER BY id;
            """;

        await using var command =
            new NpgsqlCommand(
                sql,
                connection);

        await using var reader =
            await command.ExecuteReaderAsync();

        var roles = new List<string>();

        while (await reader.ReadAsync())
        {
            roles.Add(reader.GetString(0));
        }

        Assert.NotEmpty(roles);

        Assert.Contains(
            "user",
            roles);
    }

    [Fact]
    public async Task Register_WithInvalidEmail_ShouldReturnBadRequest()
    {
        var request = new
        {
            email = "invalid-email",
            password = "Password123!"
        };

        var response = await _client.PostAsJsonAsync(
            "/api/auth/register",
            request);

        Assert.Equal(
            HttpStatusCode.BadRequest,
            response.StatusCode);

        var problemDetails =
            await response.Content.ReadFromJsonAsync<JsonElement>();

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
    public async Task Register_WithoutEmail_ShouldReturnBadRequest()
    {
        var request = new
        {
            email = "",
            password = "Password123!"
        };

        var response = await _client.PostAsJsonAsync(
            "/api/auth/register",
            request);

        Assert.Equal(
            HttpStatusCode.BadRequest,
            response.StatusCode);

        var problemDetails =
            await response.Content.ReadFromJsonAsync<JsonElement>();

        Assert.Equal(
            400,
            problemDetails.GetProperty("status").GetInt32());

        var errors =
            problemDetails.GetProperty("errors");

        Assert.True(
            errors.TryGetProperty(
                "Email",
                out _));
    }

    [Fact]
    public async Task Register_WithShortPassword_ShouldReturnBadRequest()
    {
        var request = new
        {
            email = $"integration-{Guid.NewGuid():N}@example.com",
            password = "short"
        };

        var response = await _client.PostAsJsonAsync(
            "/api/auth/register",
            request);

        Assert.Equal(
            HttpStatusCode.BadRequest,
            response.StatusCode);

        var problemDetails =
            await response.Content.ReadFromJsonAsync<JsonElement>();

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
    public async Task Register_WithDuplicateEmail_ShouldReturnConflict()
    {
        var email =
            $"duplicate-{Guid.NewGuid():N}@example.com";

        var request = new
        {
            email,
            password = "Password123!"
        };

        var firstResponse =
            await _client.PostAsJsonAsync(
                "/api/auth/register",
                request);

        Assert.Equal(
            HttpStatusCode.Created,
            firstResponse.StatusCode);

        var secondResponse =
            await _client.PostAsJsonAsync(
                "/api/auth/register",
                request);

        Assert.Equal(
            HttpStatusCode.Conflict,
            secondResponse.StatusCode);

        var problemDetails =
            await secondResponse.Content.ReadFromJsonAsync<JsonElement>();

        Assert.Equal(
            409,
            problemDetails.GetProperty("status").GetInt32());

        Assert.Equal(
            "Conflict",
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
    public async Task Register_ShouldPersistHashedPasswordAndSalt()
    {
        var password = "Password123!";
        var email =
            $"password-{Guid.NewGuid():N}@example.com";

        var request = new
        {
            email,
            password
        };

        var response = await _client.PostAsJsonAsync(
            "/api/auth/register",
            request);

        Assert.Equal(
            HttpStatusCode.Created,
            response.StatusCode);

        await using var connection =
            new NpgsqlConnection(
                _postgresFixture.ConnectionString);

        await connection.OpenAsync();

        const string sql = """
        SELECT password_hash, password_salt
        FROM public.users
        WHERE email = @email;
        """;

        await using var command =
            new NpgsqlCommand(sql, connection);

        command.Parameters.AddWithValue(
            "email",
            email);

        await using var reader =
            await command.ExecuteReaderAsync();

        Assert.True(
            await reader.ReadAsync());

        var passwordHash =
            (byte[])reader["password_hash"];

        var passwordSalt =
            (byte[])reader["password_salt"];

        Assert.NotEmpty(passwordHash);
        Assert.NotEmpty(passwordSalt);

        Assert.NotEqual(
            password,
            Convert.ToBase64String(passwordHash));

        Assert.NotEqual(
            password,
            Convert.ToBase64String(passwordSalt));
    }

    [Fact]
    public async Task Register_ShouldAllowLoginWithOriginalPassword()
    {
        var password = "Password123!";
        var email =
            $"login-{Guid.NewGuid():N}@example.com";

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
    }

    [Fact]
    public async Task Login_WithWrongPassword_ShouldReturnUnauthorized()
    {
        var email =
            $"wrong-password-{Guid.NewGuid():N}@example.com";

        var registerRequest = new
        {
            email,
            password = "Password123!"
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

        var loginResponse =
            await _client.PostAsJsonAsync(
                "/api/auth/login",
                loginRequest);

        Assert.Equal(
            HttpStatusCode.Unauthorized,
            loginResponse.StatusCode);

        var problemDetails =
            await loginResponse.Content
                .ReadFromJsonAsync<JsonElement>();

        Assert.Equal(
            401,
            problemDetails.GetProperty("status").GetInt32());

        Assert.Equal(
            "Unauthorized",
            problemDetails.GetProperty("title").GetString());
    }
}