using Authentication.Application.Exceptions;
using FluentValidation;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Mvc;

namespace Authentication.Api.ExceptionHandling
{
    public sealed class GlobalExceptionHandler(
        ILogger<GlobalExceptionHandler> logger) : IExceptionHandler
    {
        public async ValueTask<bool> TryHandleAsync(
            HttpContext httpContext,
            Exception exception,
            CancellationToken cancellationToken)
        {
            logger.LogError(
            exception,
            "Unhandled exception occurred. TraceId: {TraceId}",
            httpContext.TraceIdentifier);

            var problemDetails = exception switch
            {
                ValidationException validationException =>
                    CreateValidationProblem(
                        validationException, 
                        httpContext),

                UnauthorizedException unauthorizedException =>
                    CreateProblem(
                        StatusCodes.Status401Unauthorized,
                        "Unauthorized",
                        unauthorizedException.Message,
                        httpContext),

                ConflictException conflictException =>
                    CreateProblem(
                        StatusCodes.Status409Conflict,
                        "Conflict",
                        conflictException.Message,
                        httpContext),

                _ =>
                    CreateProblem(
                        StatusCodes.Status500InternalServerError,
                        "Internal Server Error",
                        "An unexpected error occurred.",
                        httpContext)
            };

            httpContext.Response.StatusCode = problemDetails.Status!.Value;

            await httpContext.Response.WriteAsJsonAsync(
                problemDetails,
                cancellationToken);

            return true;
        }

        private static ProblemDetails CreateValidationProblem(
            ValidationException exception,
            HttpContext httpContext)
        {
            var errors = exception.Errors
                .GroupBy(error => error.PropertyName)
                .ToDictionary(
                    group => group.Key,
                    group => group.Select(error => error.ErrorMessage).ToArray());

            var problemDetails = new ProblemDetails
            {
                Status = StatusCodes.Status400BadRequest,
                Title = "Validation failed.",
                Detail = "One or more validation errors occurred.",
                Instance = httpContext.Request.Path
            };

            problemDetails.Extensions["errors"] = errors;
            problemDetails.Extensions["traceId"] = httpContext.TraceIdentifier;

            return problemDetails;
        }

        private static ProblemDetails CreateProblem(
            int statusCode,
            string title,
            string detail,
            HttpContext httpContext)
        {
            var problemDetails = new ProblemDetails
            {
                Status = statusCode,
                Title = title,
                Detail = detail,
                Instance = httpContext.Request.Path
            };

            problemDetails.Extensions["traceId"] = httpContext.TraceIdentifier;

            return problemDetails;
        }
    }
}
