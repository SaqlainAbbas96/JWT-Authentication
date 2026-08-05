using Authentication.Application.Interfaces;
using System.Security.Cryptography;

namespace Authentication.Infrastructure.Security
{
    public class PasswordHasher : IPasswordHasher
    {
        private const int SaltSize = 32;
        private const int HashSize = 32;

        // Increase over time as hardware gets faster.
        private const int Iterations = 600000;

        private static readonly HashAlgorithmName Algorithm =
            HashAlgorithmName.SHA512;

        public (byte[] Hash, byte[] Salt) HashPassword(string password)
        {
            var salt = RandomNumberGenerator.GetBytes(SaltSize);

            var hash = Rfc2898DeriveBytes.Pbkdf2(
                password,
                salt,
                Iterations,
                Algorithm,
                HashSize);

            return (hash, salt);
        }

        public bool VerifyPassword(
            string password,
            byte[] passwordHash,
            byte[] passwordSalt)
        {
            var computedHash = Rfc2898DeriveBytes.Pbkdf2(
                password,
                passwordSalt,
                Iterations,
                Algorithm,
                HashSize);

            return CryptographicOperations.FixedTimeEquals(
                computedHash,
                passwordHash);
        }
    }
}
