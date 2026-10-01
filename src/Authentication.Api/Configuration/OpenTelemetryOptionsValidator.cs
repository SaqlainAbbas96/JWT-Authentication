using Microsoft.Extensions.Options;

namespace Authentication.Api.Configuration;

public sealed class OpenTelemetryOptionsValidator
    : IValidateOptions<OpenTelemetryOptions>
{
    public ValidateOptionsResult Validate(
        string? name,
        OpenTelemetryOptions options)
    {
        if (!options.Enabled)
        {
            return ValidateOptionsResult.Success;
        }

        if (string.IsNullOrWhiteSpace(options.Endpoint))
        {
            return ValidateOptionsResult.Fail(
                "OpenTelemetry:Endpoint is required when OpenTelemetry is enabled.");
        }

        if (!Uri.TryCreate(
                options.Endpoint,
                UriKind.Absolute,
                out var endpoint))
        {
            return ValidateOptionsResult.Fail(
                "OpenTelemetry:Endpoint must be a valid absolute URI.");
        }

        if (endpoint.Scheme is not ("http" or "https"))
        {
            return ValidateOptionsResult.Fail(
                "OpenTelemetry:Endpoint must use HTTP or HTTPS.");
        }

        return ValidateOptionsResult.Success;
    }
}