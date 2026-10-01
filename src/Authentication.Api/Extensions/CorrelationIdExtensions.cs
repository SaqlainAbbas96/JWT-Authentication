using Authentication.Api.Middleware;

namespace Authentication.Api.Extensions;

public static class CorrelationIdExtensions
{
    public static IApplicationBuilder UseCorrelationId(
        this IApplicationBuilder app)
    {
        return app.UseMiddleware<CorrelationIdMiddleware>();
    }
}