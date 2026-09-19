using Authentication.Application.Configuration;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;

namespace Authentication.Api.Extensions
{
    public static class AuthenticationExtensions
    {
        public static IServiceCollection AddJwtAuthentication(
            this IServiceCollection services)
        {
            services.AddAuthentication(
                JwtBearerDefaults.AuthenticationScheme)
                .AddJwtBearer();

            services.AddOptions<JwtBearerOptions>(
                    JwtBearerDefaults.AuthenticationScheme)
                .Configure<IOptions<JwtOptions>>(
                    (options, jwtOptions) =>
                    {
                        var settings = jwtOptions.Value;

                        var signingKey = new SymmetricSecurityKey(
                            Convert.FromBase64String(settings.Key));

                        options.TokenValidationParameters =
                            new TokenValidationParameters
                            {
                                ValidateIssuer = true,
                                ValidIssuer = settings.Issuer,

                                ValidateAudience = true,
                                ValidAudience = settings.Audience,

                                ValidateIssuerSigningKey = true,
                                IssuerSigningKey = signingKey,

                                ValidateLifetime = true,

                                RequireExpirationTime = true,
                                RequireSignedTokens = true,

                                ClockSkew = TimeSpan.Zero,

                                NameClaimType = ClaimTypes.Name,
                                RoleClaimType = ClaimTypes.Role
                            };
                    });

            services.AddAuthorization();

            return services;
        }
    }
}
