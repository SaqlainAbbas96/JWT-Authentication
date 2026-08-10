using Authentication.Application.Dtos.Requests;
using FluentValidation;

namespace Authentication.Application.Validators
{
    public sealed class LoginRequestValidator : AbstractValidator<LoginRequestDto>
    {
        public LoginRequestValidator()
        {
            RuleFor(x => x.Email)
                .NotEmpty()
                .EmailAddress();

            RuleFor(x => x.Password)
                .NotEmpty();
        }
    }
}
