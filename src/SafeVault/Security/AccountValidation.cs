using System.ComponentModel.DataAnnotations;
using System.Net.Mail;
using System.Text;
using System.Text.RegularExpressions;

namespace SafeVault.Security;

public sealed record Registration(string Username, string Email, string DisplayName, string Password);
public sealed record Login(string Username, string Password);

public static partial class AccountValidation
{
    [GeneratedRegex(@"\A[a-z0-9][a-z0-9._-]{2,31}\z", RegexOptions.CultureInvariant)]
    private static partial Regex UsernamePattern();

    public static Login ValidateLogin(string? username, string? password)
    {
        var normalized = username?.Trim().ToLowerInvariant() ?? "";
        if (ContainsControlCharacters(username) || !UsernamePattern().IsMatch(normalized))
        {
            throw new ValidationException("Use 3 to 32 letters, digits, dots, underscores, or hyphens for the username.");
        }
        if (password is null || password.Length < 12 || Encoding.UTF8.GetByteCount(password) > 72)
        {
            throw new ValidationException("Use a password of at least 12 characters and at most 72 UTF-8 bytes.");
        }
        return new Login(normalized, password);
    }

    public static Registration ValidateRegistration(string? username, string? email, string? displayName, string? password)
    {
        var login = ValidateLogin(username, password);
        var normalizedEmail = email?.Trim().ToLowerInvariant() ?? "";
        if (normalizedEmail.Length > 100 ||
            ContainsControlCharacters(email) ||
            !MailAddress.TryCreate(normalizedEmail, out var address) ||
            !string.Equals(address.Address, normalizedEmail, StringComparison.Ordinal) ||
            !address.Host.Contains('.'))
        {
            throw new ValidationException("Enter a valid email address of at most 100 characters.");
        }
        var name = displayName?.Trim() ?? "";
        if (name.Length is < 1 or > 80 || ContainsControlCharacters(displayName))
        {
            throw new ValidationException("Enter a display name from 1 to 80 characters.");
        }
        return new Registration(login.Username, normalizedEmail, name, login.Password);
    }

    public static string ValidateSearch(string? displayName)
    {
        var name = displayName?.Trim() ?? "";
        if (name.Length > 80 || ContainsControlCharacters(displayName))
        {
            throw new ValidationException("Enter a search term of at most 80 characters.");
        }
        return name;
    }

    private static bool ContainsControlCharacters(string? value) => value?.Any(char.IsControl) == true;
}
