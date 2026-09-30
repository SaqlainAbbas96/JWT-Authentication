namespace Authentication.Api.Configuration;

public sealed class OpenTelemetryOptions
{
    public const string SectionName = "OpenTelemetry";

    public bool Enabled { get; init; }

    public string Endpoint { get; init; } =
        "http://localhost:4317";
}