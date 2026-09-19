using Npgsql;

namespace Authentication.IntegrationTests.Infrastructure;

public sealed class PostgreSqlFixtureTests
    : IClassFixture<PostgreSqlFixture>
{
    private readonly PostgreSqlFixture _fixture;

    public PostgreSqlFixtureTests(
        PostgreSqlFixture fixture)
    {
        _fixture = fixture;
    }

    [Fact]
    public async Task PostgreSqlContainer_ShouldContainApplicationSchema()
    {
        await using var connection =
            new NpgsqlConnection(
                _fixture.ConnectionString);

        await connection.OpenAsync();

        const string sql = """
            SELECT COUNT(*)
            FROM information_schema.tables
            WHERE table_schema = 'public'
              AND table_name IN (
                  'users',
                  'roles',
                  'user_roles',
                  'refresh_tokens'
              );
            """;

        await using var command =
            new NpgsqlCommand(sql, connection);

        var tableCount =
            Convert.ToInt32(
                await command.ExecuteScalarAsync());

        Assert.Equal(4, tableCount);
    }
}