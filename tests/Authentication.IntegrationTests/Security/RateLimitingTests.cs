using System.Net;
using System.Net.Http.Json;
using Authentication.IntegrationTests.Infrastructure;

namespace Authentication.IntegrationTests.Security;

public sealed class RateLimitingTests
    : IClassFixture<PostgreSqlFixture>
{
    private readonly PostgreSqlFixture _fixture;

    public RateLimitingTests(
        PostgreSqlFixture fixture)
    {
        _fixture = fixture;
    }

    [Fact]
    public async Task Login_ShouldBeRateLimited_AfterRequestLimitIsExceeded()
    {
        await using var factory =
            new AuthenticationWebApplicationFactory(
                _fixture.ConnectionString);

        using var client = factory.CreateClient();

        var responses = new List<HttpResponseMessage>();

        for (var i = 0; i < 11; i++)
        {
            var response = await client.PostAsJsonAsync(
                "/api/auth/login",
                new
                {
                    email = $"ratelimit-{Guid.NewGuid()}@example.com",
                    password = "Password123!"
                });

            responses.Add(response);
        }

        Assert.Contains(
            responses,
            response =>
                response.StatusCode ==
                HttpStatusCode.TooManyRequests);
    }

    [Fact]
    public async Task Login_WhenRateLimitIsExceeded_ShouldReturnRetryAfter()
    {
        await using var factory =
            new AuthenticationWebApplicationFactory(
                _fixture.ConnectionString);

        using var client = factory.CreateClient();

        HttpResponseMessage? rateLimitedResponse = null;

        for (var i = 0; i < 11; i++)
        {
            var response = await client.PostAsJsonAsync(
                "/api/auth/login",
                new
                {
                    email = $"retry-after-{Guid.NewGuid()}@example.com",
                    password = "Password123!"
                });

            if (response.StatusCode ==
                HttpStatusCode.TooManyRequests)
            {
                rateLimitedResponse = response;
                break;
            }
        }

        Assert.NotNull(rateLimitedResponse);

        Assert.True(
            rateLimitedResponse!.Headers.TryGetValues(
                "Retry-After",
                out var retryAfterValues));

        Assert.Contains(
            retryAfterValues,
            value => int.TryParse(value, out var seconds) &&
                     seconds > 0);
    }

    [Fact]
    public async Task Register_ShouldBeRateLimited_AfterRequestLimitIsExceeded()
    {
        await using var factory =
            new AuthenticationWebApplicationFactory(
                _fixture.ConnectionString);

        using var client = factory.CreateClient();

        HttpResponseMessage? rateLimitedResponse = null;

        for (var i = 0; i < 11; i++)
        {
            var response = await client.PostAsJsonAsync(
                "/api/auth/register",
                new
                {
                    email = $"register-ratelimit-{Guid.NewGuid()}@example.com",
                    password = "Password123!"
                });

            if (response.StatusCode ==
                HttpStatusCode.TooManyRequests)
            {
                rateLimitedResponse = response;
                break;
            }
        }

        Assert.NotNull(rateLimitedResponse);

        Assert.Equal(
            HttpStatusCode.TooManyRequests,
            rateLimitedResponse!.StatusCode);
    }

    [Fact]
    public async Task RefreshToken_ShouldBeRateLimited_AfterRequestLimitIsExceeded()
    {
        await using var factory =
            new AuthenticationWebApplicationFactory(
                _fixture.ConnectionString);

        using var client = factory.CreateClient();

        HttpResponseMessage? rateLimitedResponse = null;

        for (var i = 0; i < 11; i++)
        {
            var response = await client.PostAsJsonAsync(
                "/api/auth/refresh-token",
                new
                {
                    refreshToken = $"invalid-token-{Guid.NewGuid()}"
                });

            if (response.StatusCode ==
                HttpStatusCode.TooManyRequests)
            {
                rateLimitedResponse = response;
                break;
            }
        }

        Assert.NotNull(rateLimitedResponse);

        Assert.Equal(
            HttpStatusCode.TooManyRequests,
            rateLimitedResponse!.StatusCode);
    }
}