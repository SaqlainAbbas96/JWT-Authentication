using System.Threading.RateLimiting;

namespace Authentication.Api.Extensions;

public static class RateLimitingExtensions
{
    public const string AuthenticationPolicy = "authentication";

    public static IServiceCollection AddAuthenticationRateLimiting(
        this IServiceCollection services)
    {
        services.AddRateLimiter(options =>
        {
            options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;

            options.OnRejected = async (
                context,
                cancellationToken) =>
            {
                if (context.Lease.TryGetMetadata(
                        MetadataName.RetryAfter,
                        out var retryAfter))
                {
                    context.HttpContext.Response.Headers.RetryAfter =
                        ((int)Math.Ceiling(retryAfter.TotalSeconds))
                            .ToString();
                }

                await Results.Problem(
                    statusCode: StatusCodes.Status429TooManyRequests,
                    title: "Too Many Requests",
                    detail: "Too many authentication requests. Please try again later.")
                    .ExecuteAsync(context.HttpContext);
            };

            options.AddPolicy(
                AuthenticationPolicy,
                httpContext =>
                    RateLimitPartition.GetFixedWindowLimiter(
                        GetClientIdentifier(httpContext),
                        _ => new FixedWindowRateLimiterOptions
                        {
                            PermitLimit = 10,
                            Window = TimeSpan.FromMinutes(1),
                            QueueLimit = 0,
                            AutoReplenishment = true
                        }));
        });

        return services;
    }

    private static string GetClientIdentifier(
        HttpContext httpContext)
    {
        return httpContext.Connection.RemoteIpAddress?
                   .ToString()
               ?? "unknown";
    }
}