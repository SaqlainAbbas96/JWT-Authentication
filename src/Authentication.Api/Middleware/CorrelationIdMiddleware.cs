using System.Diagnostics;

namespace Authentication.Api.Middleware;

public sealed class CorrelationIdMiddleware
{
    private const string HeaderName = "X-Correlation-ID";

    private readonly RequestDelegate _next;
    private readonly ILogger<CorrelationIdMiddleware> _logger;

    public CorrelationIdMiddleware(
        RequestDelegate next,
        ILogger<CorrelationIdMiddleware> logger)
    {
        _next = next;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        var correlationId = GetCorrelationId(context);

        context.Response.Headers[HeaderName] = correlationId;

        var activity = Activity.Current;

        using var scope =
            _logger.BeginScope(
                new Dictionary<string, object>
                {
                    ["CorrelationId"] = correlationId,
                    ["TraceId"] = activity?.TraceId.ToString(),
                    ["SpanId"] = activity?.SpanId.ToString()
                });

        context.Items[HeaderName] = correlationId;

        _logger.LogDebug(
            "Request started. Method: {Method}, Path: {Path}.",
            context.Request.Method,
            context.Request.Path);

        try
        {
            await _next(context);
        }
        finally
        {
            _logger.LogDebug(
                "Request completed. StatusCode: {StatusCode}.",
                context.Response.StatusCode);
        }
    }

    private static string GetCorrelationId(
        HttpContext context)
    {
        if (context.Request.Headers.TryGetValue(
                HeaderName,
                out var headerValue) &&
            Guid.TryParseExact(
                headerValue.ToString(),
                "D",
                out var correlationId))
        {
            return correlationId.ToString("D");
        }

        return Guid.NewGuid().ToString("D");
    }
}