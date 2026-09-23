using Microsoft.Extensions.Options;

namespace Authentication.Api.Configuration
{
    public class CorsOptionsValidator : IValidateOptions<CorsOptions>
    {
        public ValidateOptionsResult Validate(
            string? name,
            CorsOptions options)
        {
            var failures = new List<string>();

            if (options.AllowedOrigins.Length == 0)
            {
                failures.Add(
                    "Cors:AllowedOrigins must contain at least one origin.");
            }

            for (var index = 0;
                 index < options.AllowedOrigins.Length;
                 index++)
            {
                var origin = options.AllowedOrigins[index];

                if (string.IsNullOrWhiteSpace(origin))
                {
                    failures.Add(
                        $"Cors:AllowedOrigins[{index}] must not be empty.");

                    continue;
                }

                if (!Uri.TryCreate(
                        origin,
                        UriKind.Absolute,
                        out var uri))
                {
                    failures.Add(
                        $"Cors:AllowedOrigins[{index}] must be a valid absolute URI.");

                    continue;
                }

                if (uri.Scheme is not ("http" or "https") ||
                    string.IsNullOrWhiteSpace(uri.Host))
                {
                    failures.Add(
                        $"Cors:AllowedOrigins[{index}] must be an HTTP or HTTPS origin.");
                }

                if (uri.AbsolutePath != "/" ||
                    !string.IsNullOrEmpty(uri.Query) ||
                    !string.IsNullOrEmpty(uri.Fragment))
                {
                    failures.Add(
                        $"Cors:AllowedOrigins[{index}] must contain only scheme, host, and optional port.");
                }

                if (origin.EndsWith('/'))
                {
                    failures.Add(
                        $"Cors:AllowedOrigins[{index}] must not have a trailing slash.");
                }
            }

            return failures.Count > 0
                ? ValidateOptionsResult.Fail(failures)
                : ValidateOptionsResult.Success;
        }
    }
}
