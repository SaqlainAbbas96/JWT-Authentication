using Authentication.Api.Middleware;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;

namespace Authentication.IntegrationTests.Middleware;

public sealed class CorrelationIdTests
{
    [Fact]
    public async Task InvokeAsync_WhenCorrelationIdIsMissing_ShouldGenerateCorrelationId()
    {
        // Arrange
        var context = new DefaultHttpContext();

        var middleware = new CorrelationIdMiddleware(
            _ => Task.CompletedTask,
            NullLogger<CorrelationIdMiddleware>.Instance);

        // Act
        await middleware.InvokeAsync(context);

        // Assert
        var correlationId =
            context.Response.Headers["X-Correlation-ID"].ToString();

        Assert.True(Guid.TryParse(correlationId, out _));
    }

    [Fact]
    public async Task InvokeAsync_WhenValidCorrelationIdIsProvided_ShouldPreserveCorrelationId()
    {
        // Arrange
        var correlationId = Guid.NewGuid().ToString();

        var context = new DefaultHttpContext();
        context.Request.Headers["X-Correlation-ID"] = correlationId;

        var middleware = new CorrelationIdMiddleware(
            _ => Task.CompletedTask,
            NullLogger<CorrelationIdMiddleware>.Instance);

        // Act
        await middleware.InvokeAsync(context);

        // Assert
        Assert.Equal(
            correlationId,
            context.Response.Headers["X-Correlation-ID"].ToString());
    }
}