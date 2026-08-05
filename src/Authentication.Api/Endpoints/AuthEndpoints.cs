using Authentication.Application.Dtos.Requests;
using Authentication.Application.Interfaces;

namespace Authentication.Api.Endpoints
{
    public static class AuthEndpoints
    {
        public static IEndpointRouteBuilder MapAuthEndpoints(this IEndpointRouteBuilder app)
        {
            var group = app.MapGroup("/api/auth")
                .WithTags("Authentication");

            // Register
            group.MapPost("/register",
                async (RegisterRequestDto userDto, IUserService userService) =>
                {
                    var result = await userService.RegisterUser(userDto);

                    return Results.Created($"/api/users/{result.UserId}", result);
                })
            .WithName("Register")
            .WithSummary("Register a new user")
            .WithDescription("Creates a new user account.");

            // Login
            group.MapPost("/login",
                async (LoginRequestDto loginDto, IUserService userService) =>
                {
                    var result = await userService.Authenticate(loginDto);

                    return Results.Ok(result);
                })
            .WithName("Login")
            .WithSummary("Authenticate user")
            .WithDescription("Authenticates a user and returns a JWT.");

            return app;
        }
    }
}
