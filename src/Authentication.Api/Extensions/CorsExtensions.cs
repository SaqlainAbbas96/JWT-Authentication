using Authentication.Api.Configuration;
using Microsoft.Extensions.Options;

namespace Authentication.Api.Extensions;

public static class CorsExtensions
{
    public const string PolicyName = "ApiCors";

    public static IServiceCollection AddApiCors(
        this IServiceCollection services)
    {
        services.AddOptions<CorsOptions>()
            .BindConfiguration(CorsOptions.SectionName)
            .ValidateOnStart();

        services.AddSingleton<
            IValidateOptions<CorsOptions>,
            CorsOptionsValidator>();

        services.AddCors();

        return services;
    }

    public static IApplicationBuilder UseApiCors(
        this IApplicationBuilder app)
    {
        var corsOptions =
            app.ApplicationServices
                .GetRequiredService<IOptions<CorsOptions>>()
                .Value;

        return app.UseCors(policy =>
        {
            policy
                .WithOrigins(corsOptions.AllowedOrigins)
                .WithMethods(
                    "GET",
                    "POST",
                    "PUT",
                    "PATCH",
                    "DELETE",
                    "OPTIONS")
                .WithHeaders(
                    "Authorization",
                    "Content-Type");
        });
    }
}