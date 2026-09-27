using Microsoft.AspNetCore.Diagnostics.HealthChecks;

namespace Authentication.Api.Endpoints;

public static class HealthEndpoints
{
    public static IEndpointRouteBuilder MapHealthEndpoints(
        this IEndpointRouteBuilder app)
    {
        app.MapHealthChecks(
                "/health/live",
                new HealthCheckOptions
                {
                    Predicate = _ => false
                })
            .AllowAnonymous()
            .WithTags("Health")
            .WithName("Liveness")
            .WithSummary("Checks whether the API process is running.")
            .WithDescription(
                "Returns healthy when the API process is running. "
                + "No external dependencies are checked.");

        app.MapHealthChecks(
                "/health/ready",
                new HealthCheckOptions
                {
                    Predicate = check =>
                        check.Tags.Contains("ready")
                })
            .AllowAnonymous()
            .WithTags("Health")
            .WithName("Readiness")
            .WithSummary("Checks whether the API is ready to serve requests.")
            .WithDescription(
                "Checks the dependencies required by the API, "
                + "including PostgreSQL.");

        return app;
    }
}