using Npgsql;
using Testcontainers.PostgreSql;

namespace Authentication.IntegrationTests.Infrastructure;

public sealed class PostgreSqlFixture : IAsyncLifetime
{
    private readonly PostgreSqlContainer _container =
        new PostgreSqlBuilder("postgres:16")
            .WithDatabase("authentication_test")
            .WithUsername("postgres")
            .WithPassword("postgres")
            .Build();

    public string ConnectionString =>
        _container.GetConnectionString();

    public async ValueTask InitializeAsync()
    {
        await _container.StartAsync();

        await InitializeDatabaseAsync();
    }

    public async ValueTask DisposeAsync()
    {
        await _container.DisposeAsync();
    }

    private async Task InitializeDatabaseAsync()
    {
        await ExecuteSqlFileAsync(
            "DatabaseSchema.sql");

        await ExecuteSqlFileAsync(
            "DatabaseSeed.sql");
    }

    private async Task ExecuteSqlFileAsync(
        string fileName)
    {
        var filePath = Path.Combine(
            AppContext.BaseDirectory,
            "Infrastructure",
            fileName);

        var sql = await File.ReadAllTextAsync(
            filePath);

        await using var connection =
            new NpgsqlConnection(ConnectionString);

        await connection.OpenAsync();

        await using var command =
            new NpgsqlCommand(
                sql,
                connection);

        await command.ExecuteNonQueryAsync();
    }
}