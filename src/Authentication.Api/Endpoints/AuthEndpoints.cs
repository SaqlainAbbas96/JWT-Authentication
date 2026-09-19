using Authentication.Api.Filters;
using Authentication.Application.Dtos.Requests;
using Authentication.Application.Dtos.Responses;
using Authentication.Application.Interfaces;

namespace Authentication.Api.Endpoints
{
    public static class AuthEndpoints
    {
        public static IEndpointRouteBuilder MapAuthEndpoints(this IEndpointRouteBuilder app)
        {
            var group = app.MapGroup("/api/auth")
                .WithTags("Authentication");

            group.MapPost("/register",
                async (RegisterRequestDto userDto, IUserService userService) =>
                {
                    var result = await userService.RegisterUser(userDto);

                    return Results.Created($"/api/users/{result.UserId}", result);
                })
            .WithName("Register")
            .WithSummary("Register a new user")
            .WithDescription("Creates a new user account.")
            .AddEndpointFilter<ValidationFilter<RegisterRequestDto>>();

            group.MapPost("/login",
                async (LoginRequestDto loginDto, IUserService userService) =>
                {
                    var result = await userService.Authenticate(loginDto);

                    return Results.Ok(result);
                })
            .WithName("Login")
            .WithSummary("Authenticate user")
            .WithDescription("Authenticates a user and returns a JWT.")
            .AddEndpointFilter<ValidationFilter<LoginRequestDto>>();

            group.MapPost("/refresh-token",
                async (
                    RefreshTokenRequestDto request,
                    IRefreshTokenService refreshTokenService) =>
                {
                    var result =
                        await refreshTokenService.RotateTokenAsync(
                            request.RefreshToken);

                    return Results.Ok(new LoginResponseDto
                    {
                        AccessToken = result.AccessToken,
                        RefreshToken = result.RefreshToken,
                        TokenType = "Bearer",
                        ExpiresAt = result.AccessTokenExpiresAt
                    });
                })
            .WithName("RefreshAccessToken")
            .WithSummary("Refresh access token")
            .WithDescription("Issues a new access token and rotates the refresh token. "
            + "The submitted refresh token is invalidated after successful use.")
            .AddEndpointFilter<ValidationFilter<RefreshTokenRequestDto>>();

            group.MapPost("/logout",
                async (
                    RefreshTokenRequestDto request,
                    IRefreshTokenService refreshTokenService) =>
                {
                    await refreshTokenService.RevokeTokenFamilyAsync(request.RefreshToken);
                    return Results.NoContent();
                })
            .WithName("Logout")
            .WithSummary("Log out the current session")
            .WithDescription("Revokes the refresh token family associated with the supplied refresh token. " 
            + "This invalidates the current session and prevents the refresh token from being used again.")
            .AddEndpointFilter<ValidationFilter<RefreshTokenRequestDto>>();

            return app;
        }
    }
}
