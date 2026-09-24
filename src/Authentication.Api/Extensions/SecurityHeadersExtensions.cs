using Authentication.Api.Middleware;

namespace Authentication.Api.Extensions
{
    public static class SecurityHeadersExtensions
    {
        public static IApplicationBuilder UseSecurityHeaders(
            this IApplicationBuilder app)
        {
            return app.UseMiddleware<SecurityHeadersMiddleware>();
        }
    }
}
