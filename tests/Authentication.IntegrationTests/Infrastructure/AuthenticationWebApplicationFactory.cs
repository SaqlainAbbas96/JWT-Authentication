using Authentication.Infrastructure.Persistence;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Authentication.IntegrationTests.Infrastructure
{
    public sealed class AuthenticationWebApplicationFactory
        : WebApplicationFactory<Program>
    {
        private const string TestJwtKey =
            "VGhpc0lzQVN1ZmZpY2llbnRseUxvbmdUZXN0SldUS2V5Rm9ySW50ZWdyYXRpb25UZXN0aW5nMTIzNDU2Nzg5MDEyMzQ1Njc4OTA=";

        private readonly string _connectionString;
        private readonly int _refreshTokenExpirationDays;

        public AuthenticationWebApplicationFactory(
            string connectionString,
            int refreshTokenExpirationDays = 7)
        {
            _connectionString = connectionString;
            _refreshTokenExpirationDays = refreshTokenExpirationDays;
        }

        public string JwtKey =>
            TestJwtKey;

        protected override void ConfigureWebHost(
            IWebHostBuilder builder)
        {
            builder.UseEnvironment("Testing");

            builder.ConfigureAppConfiguration(
            (_, configuration) =>
            {
                configuration.AddInMemoryCollection(
                    new Dictionary<string, string?>
                    {
                        ["Jwt:Key"] = TestJwtKey,
                        ["Jwt:Issuer"] = "Authentication.Api",
                        ["Jwt:Audience"] = "Authentication.Client",
                        ["Jwt:AccessTokenExpirationMinutes"] = "15",
                        ["Jwt:RefreshTokenExpirationDays"] = _refreshTokenExpirationDays.ToString()
                    });
            });

            builder.ConfigureServices(services =>
            {
                var dbContextOptionsDescriptor =
                    services.SingleOrDefault(
                        serviceDescriptor =>
                            serviceDescriptor.ServiceType ==
                            typeof(DbContextOptions<DBContext>));

                if (dbContextOptionsDescriptor is not null)
                {
                    services.Remove(
                        dbContextOptionsDescriptor);
                }

                services.AddDbContext<DBContext>(
                    options =>
                        options.UseNpgsql(
                            _connectionString));
            });
        }
    }
}
