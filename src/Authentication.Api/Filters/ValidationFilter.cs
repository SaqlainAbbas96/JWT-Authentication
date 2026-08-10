using FluentValidation;

namespace Authentication.Api.Filters
{
    public sealed class ValidationFilter<TRequest>(
        IValidator<TRequest> validator) : IEndpointFilter 
        where TRequest : class
    {
        public async ValueTask<object?> InvokeAsync(
            EndpointFilterInvocationContext context,
            EndpointFilterDelegate next)
        {
            var request = context.Arguments
                .OfType<TRequest>()
                .FirstOrDefault();

            if (request is null)
                throw new ValidationException("Request body is required.");

            var result = await validator.ValidateAsync(request);

            if (!result.IsValid)
                throw new ValidationException(result.Errors);

            return await next(context);
        }
    }
}
