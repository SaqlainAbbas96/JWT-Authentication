using Authentication.Api.Configuration;
using OpenTelemetry.Metrics;
using OpenTelemetry.Resources;
using OpenTelemetry.Trace;

namespace Authentication.Api.Extensions;

public static class OpenTelemetryExtensions
{
    private const string ServiceName = "Authentication.Api";

    public static IServiceCollection AddApiOpenTelemetry(
        this IServiceCollection services,
        IHostEnvironment environment,
        IConfiguration configuration)
    {
        var options =
            configuration
                .GetSection(OpenTelemetryOptions.SectionName)
                .Get<OpenTelemetryOptions>()
            ?? new OpenTelemetryOptions();

        services
            .AddOpenTelemetry()
            .ConfigureResource(resource =>
                resource
                    .AddService(
                        serviceName: ServiceName,
                        serviceVersion:
                            typeof(Program)
                                .Assembly
                                .GetName()
                                .Version?
                                .ToString()
                            ?? "unknown")
                    .AddAttributes(
                    [
                        new KeyValuePair<string, object>(
                            "deployment.environment.name",
                            environment.EnvironmentName)
                    ]))
            .WithTracing(tracing =>
            {
                tracing
                    .AddAspNetCoreInstrumentation()
                    .AddHttpClientInstrumentation()
                    .AddEntityFrameworkCoreInstrumentation();

                if (options.Enabled)
                {
                    tracing.AddOtlpExporter(exporter =>
                    {
                        exporter.Endpoint =
                            new Uri(options.Endpoint);
                    });
                }
            })
            .WithMetrics(metrics =>
            {
                metrics
                    .AddAspNetCoreInstrumentation()
                    .AddRuntimeInstrumentation();

                if (options.Enabled)
                {
                    metrics.AddOtlpExporter(exporter =>
                    {
                        exporter.Endpoint =
                            new Uri(options.Endpoint);
                    });
                }
            });

        return services;
    }
}