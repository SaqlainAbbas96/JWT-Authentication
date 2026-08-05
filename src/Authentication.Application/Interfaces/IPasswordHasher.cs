namespace Authentication.Application.Interfaces
{
    public interface IPasswordHasher
    {
        (byte[] Hash, byte[] Salt) HashPassword(string password);

        bool VerifyPassword(
            string password,
            byte[] passwordHash,
            byte[] passwordSalt);
    }
}
