using Authentication.Application.Configuration;
using Authentication.Api.Extensions;
using Authentication.Application.Interfaces;
using Authentication.Application.Services;
using Authentication.Infrastructure.Identity;
using Authentication.Infrastructure.Persistence;
using Authentication.Infrastructure.Repositories;
using Microsoft.EntityFrameworkCore;

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

builder.Services.AddScoped<IUserService, UserService>();
builder.Services.AddScoped<IUserRepository, UserRepository>();
builder.Services.AddScoped<IJwtAuthenticationService, JwtAuthenticationService>();

builder.Services.AddSingleton<IHttpContextAccessor, HttpContextAccessor>();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}

app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();
