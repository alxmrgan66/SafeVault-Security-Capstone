using System.Security.Cryptography;
using BCryptHasher = BCrypt.Net.BCrypt;

namespace SafeVault.Security;

public static class Passwords
{
    private const int WorkFactor = 12;
    private static readonly string Placeholder = Hash(Convert.ToHexString(RandomNumberGenerator.GetBytes(24)));

    public static string Hash(string password) => BCryptHasher.HashPassword(password, workFactor: WorkFactor);

    public static bool Verify(string password, string? storedHash)
    {
        var matches = BCryptHasher.Verify(password, storedHash ?? Placeholder);
        return matches && storedHash is not null;
    }
}
