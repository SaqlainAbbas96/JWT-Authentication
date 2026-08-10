namespace Authentication.Application.Exceptions
{
    public sealed class UnauthorizedException(string message) : Exception(message);
}
