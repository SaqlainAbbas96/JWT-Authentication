using Authentication.IntegrationTests.Infrastructure;

namespace Authentication.IntegrationTests.Security;

public sealed class SecurityHeadersTests
    : IClassFixture<PostgreSqlFixture>
{
    private readonly PostgreSqlFixture _fixture;

    public SecurityHeadersTests(
        PostgreSqlFixture fixture)
    {
        _fixture = fixture;
    }

    [Fact]
    public async Task ApiResponse_ShouldIncludeSecurityHeaders()
    {
        await using var factory =
            new AuthenticationWebApplicationFactory(
                _fixture.ConnectionString);

        using var client = factory.CreateClient();

        using var response =
            await client.GetAsync("/api/auth/login");

        Assert.Equal(
            "nosniff",
            response.Headers.GetValues(
                "X-Content-Type-Options")
                .Single());

        Assert.Equal(
            "DENY",
            response.Headers.GetValues(
                "X-Frame-Options")
                .Single());

        Assert.Equal(
            "no-referrer",
            response.Headers.GetValues(
                "Referrer-Policy")
                .Single());

        Assert.Equal(
            "camera=(), microphone=(), geolocation=()",
            response.Headers.GetValues(
                "Permissions-Policy")
                .Single());
    }
}