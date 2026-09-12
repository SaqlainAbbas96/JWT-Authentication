using Microsoft.Extensions.Options;

namespace Authentication.Application.Configuration
{
    public sealed class JwtOptionsValidator : IValidateOptions<JwtOptions>
    {
        private const int RequiredKeySizeInBytes = 64;

        public ValidateOptionsResult Validate(
            string? name,
            JwtOptions options)
        {
            var failures = new List<string>();

            if (string.IsNullOrWhiteSpace(options.Key))
            {
                failures.Add("Jwt:Key is required.");
            }
            else
            {
                try
                {
                    var keyBytes = Convert.FromBase64String(options.Key);

                    if (keyBytes.Length < RequiredKeySizeInBytes)
                    {
                        failures.Add(
                            $"Jwt:Key must decode to at least {RequiredKeySizeInBytes} bytes.");
                    }
                }
                catch (FormatException)
                {
                    failures.Add(
                        "Jwt:Key must be a valid Base64-encoded value.");
                }
            }

            if (string.IsNullOrWhiteSpace(options.Issuer))
            {
                failures.Add("Jwt:Issuer is required.");
            }

            if (string.IsNullOrWhiteSpace(options.Audience))
            {
                failures.Add("Jwt:Audience is required.");
            }

            if (options.AccessTokenExpirationMinutes <= 0)
            {
                failures.Add(
                    "Jwt:AccessTokenExpirationMinutes must be greater than zero.");
            }

            return failures.Count > 0
                ? ValidateOptionsResult.Fail(failures)
                : ValidateOptionsResult.Success;
        }
    }
}
