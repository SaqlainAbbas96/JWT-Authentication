using Authentication.Application.Dtos.Requests;
using FluentValidation;

namespace Authentication.Application.Validators
{
    public sealed class RefreshTokenRequestValidator : AbstractValidator<RefreshTokenRequestDto>
    {
        public RefreshTokenRequestValidator()
        {
            RuleFor(x => x.RefreshToken)
                .NotEmpty();
        }
    }
}
