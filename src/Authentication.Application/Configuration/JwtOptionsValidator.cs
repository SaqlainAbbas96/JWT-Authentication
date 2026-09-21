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

            ValidateKey(options, failures);
            ValidateIssuer(options, failures);
            ValidateAudience(options, failures);
            ValidateExpirationSettings(options, failures);

            return failures.Count > 0
                ? ValidateOptionsResult.Fail(failures)
                : ValidateOptionsResult.Success;
        }

        private static void ValidateKey(
            JwtOptions options,
            List<string> failures)
        {
            if (string.IsNullOrWhiteSpace(options.Key))
            {
                failures.Add("Jwt:Key is required.");
                return;
            }
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

        private static void ValidateIssuer(
            JwtOptions options,
            List<string> failures)
        {
            if (string.IsNullOrWhiteSpace(options.Issuer))
            {
                failures.Add("Jwt:Issuer is required.");
            }
        }

        private static void ValidateAudience(
            JwtOptions options,
            List<string> failures)
        {
            if (string.IsNullOrWhiteSpace(options.Audience))
            {
                failures.Add("Jwt:Audience is required.");
            }
        }

        private static void ValidateExpirationSettings(
            JwtOptions options,
            List<string> failures)
        {
            if (options.AccessTokenExpirationMinutes <= 0)
            {
                failures.Add(
                    "Jwt:AccessTokenExpirationMinutes must be greater than zero.");
            }

            if (options.RefreshTokenExpirationDays <= 0)
            {
                failures.Add(
                    "Jwt:RefreshTokenExpirationDays must be greater than zero.");
            }
        }
    }
}
