using Microsoft.Extensions.Options;

namespace Authentication.Api.Configuration;

public sealed class ConnectionStringOptions
{
    public const string SectionName = "ConnectionStrings";

    public string Postgres { get; init; } = string.Empty;
}

public sealed class ConnectionStringOptionsValidator
    : IValidateOptions<ConnectionStringOptions>
{
    public ValidateOptionsResult Validate(
        string? name,
        ConnectionStringOptions options)
    {
        if (string.IsNullOrWhiteSpace(options.Postgres))
        {
            return ValidateOptionsResult.Fail(
                "ConnectionStrings:Postgres is required.");
        }

        return ValidateOptionsResult.Success;
    }
}