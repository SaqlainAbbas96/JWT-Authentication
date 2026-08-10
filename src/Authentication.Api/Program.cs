using Authentication.Api.Endpoints;
using Authentication.Api.ExceptionHandling;
using Authentication.Api.Extensions;
using Authentication.Application.Configuration;
using Authentication.Application.Interfaces;
using Authentication.Application.Services;
using Authentication.Application.Validators;
using Authentication.Infrastructure.Identity;
using Authentication.Infrastructure.Persistence;
using Authentication.Infrastructure.Repositories;
using Authentication.Infrastructure.Security;
using Microsoft.EntityFrameworkCore;
using Scalar.AspNetCore;
using FluentValidation;

var builder = WebApplication.CreateBuilder(args);

// Configure JWT options
builder.Services.Configure<JwtOptions>(
    builder.Configuration.GetRequiredSection("Jwt"));

// Configure JWT authentication
AuthenticationExtensions.Configure(builder.Services, builder.Configuration);

// Add services to the container.
builder.Services.AddControllers();
builder.Services.AddOpenApi();

builder.Services.AddDbContext<DBContext>(options =>
    options.UseNpgsql(builder.Configuration.GetConnectionString("Postgres")));

builder.Services.AddExceptionHandler<GlobalExceptionHandler>();
builder.Services.AddProblemDetails();

builder.Services.AddValidatorsFromAssemblyContaining<LoginRequestValidator>();

builder.Services.AddScoped<IUserService, UserService>();
builder.Services.AddScoped<IUserRepository, UserRepository>();
builder.Services.AddScoped<IJwtAuthenticationService, JwtAuthenticationService>();

builder.Services.AddScoped<IPasswordHasher, PasswordHasher>();

builder.Services.AddSingleton<IHttpContextAccessor, HttpContextAccessor>();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();

    app.MapScalarApiReference();
}

app.UseHttpsRedirection();

app.UseExceptionHandler();

app.UseAuthentication();
app.UseAuthorization();

app.MapAuthEndpoints();

app.Run();
