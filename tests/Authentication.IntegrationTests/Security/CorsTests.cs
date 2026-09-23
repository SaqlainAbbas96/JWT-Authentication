using System.Net;
using Authentication.IntegrationTests.Infrastructure;

namespace Authentication.IntegrationTests.Security;

public sealed class CorsTests
    : IClassFixture<PostgreSqlFixture>
{
    private const string AllowedOrigin =
        "https://test-client.example.com";

    private const string DisallowedOrigin =
        "https://malicious.example.com";

    private readonly PostgreSqlFixture _fixture;

    public CorsTests(
        PostgreSqlFixture fixture)
    {
        _fixture = fixture;
    }

    [Fact]
    public async Task Request_FromAllowedOrigin_ShouldReturnCorsHeaders()
    {
        await using var factory =
            new AuthenticationWebApplicationFactory(
                _fixture.ConnectionString);

        using var client = factory.CreateClient();

        using var request =
            new HttpRequestMessage(
                HttpMethod.Options,
                "/api/auth/login");

        request.Headers.Add(
            "Origin",
            AllowedOrigin);

        request.Headers.Add(
            "Access-Control-Request-Method",
            "POST");

        request.Headers.Add(
            "Access-Control-Request-Headers",
            "content-type");

        using var response =
            await client.SendAsync(request);

        Assert.Equal(
            HttpStatusCode.NoContent,
            response.StatusCode);

        Assert.True(
            response.Headers.TryGetValues(
                "Access-Control-Allow-Origin",
                out var origins));

        Assert.Contains(
            AllowedOrigin,
            origins);
    }

    [Fact]
    public async Task Request_FromDisallowedOrigin_ShouldNotReturnAllowOriginHeader()
    {
        await using var factory =
            new AuthenticationWebApplicationFactory(
                _fixture.ConnectionString);

        using var client = factory.CreateClient();

        using var request =
            new HttpRequestMessage(
                HttpMethod.Options,
                "/api/auth/login");

        request.Headers.Add(
            "Origin",
            DisallowedOrigin);

        request.Headers.Add(
            "Access-Control-Request-Method",
            "POST");

        request.Headers.Add(
            "Access-Control-Request-Headers",
            "content-type");

        using var response =
            await client.SendAsync(request);

        Assert.False(
            response.Headers.Contains(
                "Access-Control-Allow-Origin"));
    }

    [Fact]
    public async Task ActualRequest_FromAllowedOrigin_ShouldReturnCorsHeader()
    {
        await using var factory =
            new AuthenticationWebApplicationFactory(
                _fixture.ConnectionString);

        using var client = factory.CreateClient();

        using var request =
            new HttpRequestMessage(
                HttpMethod.Post,
                "/api/auth/login");

        request.Headers.Add(
            "Origin",
            AllowedOrigin);

        using var response =
            await client.SendAsync(request);

        Assert.True(
            response.Headers.TryGetValues(
                "Access-Control-Allow-Origin",
                out var origins));

        Assert.Contains(
            AllowedOrigin,
            origins);
    }
}