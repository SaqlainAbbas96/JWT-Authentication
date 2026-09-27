using System.Net;
using Authentication.IntegrationTests.Infrastructure;

namespace Authentication.IntegrationTests.Health;

public sealed class HealthEndpointTests
    : IClassFixture<PostgreSqlFixture>,
      IAsyncLifetime
{
    private readonly PostgreSqlFixture _postgresFixture;

    private AuthenticationWebApplicationFactory _factory = null!;
    private HttpClient _client = null!;

    public HealthEndpointTests(
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
    public async Task Live_ShouldReturnHealthy()
    {
        var response =
            await _client.GetAsync("/health/live");

        Assert.Equal(
            HttpStatusCode.OK,
            response.StatusCode);

        var content =
            await response.Content.ReadAsStringAsync();

        Assert.Equal(
            "Healthy",
            content);
    }

    [Fact]
    public async Task Ready_ShouldReturnHealthy_WhenDatabaseIsAvailable()
    {
        var response =
            await _client.GetAsync("/health/ready");

        Assert.Equal(
            HttpStatusCode.OK,
            response.StatusCode);

        var content =
            await response.Content.ReadAsStringAsync();

        Assert.Equal(
            "Healthy",
            content);
    }
}