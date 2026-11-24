using System.Globalization;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using SafeVault.Data;

namespace SafeVault.Security;

public sealed class AccountSessions(AccountStore store, TimeProvider clock)
{
    internal const string SessionClaim = "safevault_session";
    internal const string DisplayNameClaim = "safevault_display_name";
    internal static readonly TimeSpan Lifetime = TimeSpan.FromMinutes(30);

    public async Task SignInAsync(HttpContext context, Account account)
    {
        var sessionId = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
        var expiry = clock.GetUtcNow().Add(Lifetime);
        store.StartSession(account.Id, Digest(sessionId), expiry);
        var properties = new AuthenticationProperties { ExpiresUtc = expiry };
        await context.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme,
            PrincipalFor(account, sessionId), properties);
    }

    public async Task SignOutAsync(HttpContext context)
    {
        var sessionId = context.User.FindFirstValue(SessionClaim);
        if (sessionId is not null)
        {
            store.EndSession(Digest(sessionId));
        }
        await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
    }

    internal static string Digest(string sessionId) =>
        Convert.ToHexString(SHA256.HashData(Encoding.ASCII.GetBytes(sessionId)));

    internal static ClaimsPrincipal PrincipalFor(Account account, string sessionId)
    {
        Claim[] claims =
        [
            new(ClaimTypes.NameIdentifier, account.Id.ToString(CultureInfo.InvariantCulture)),
            new(ClaimTypes.Name, account.Username),
            new(ClaimTypes.Email, account.Email),
            new(ClaimTypes.Role, account.Role),
            new(DisplayNameClaim, account.DisplayName),
            new(SessionClaim, sessionId)
        ];
        return new ClaimsPrincipal(new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme));
    }
}

public sealed class VaultCookieEvents(AccountStore store, TimeProvider clock) : CookieAuthenticationEvents
{
    public override Task ValidatePrincipal(CookieValidatePrincipalContext context)
    {
        var sessionId = context.Principal?.FindFirstValue(AccountSessions.SessionClaim);
        var account = sessionId is null ? null : store.FindSession(AccountSessions.Digest(sessionId), clock.GetUtcNow());
        if (sessionId is null || account is null)
        {
            context.RejectPrincipal();
            return context.HttpContext.SignOutAsync(context.Scheme.Name);
        }

        context.ReplacePrincipal(AccountSessions.PrincipalFor(account, sessionId));
        return Task.CompletedTask;
    }

    public override Task RedirectToAccessDenied(RedirectContext<CookieAuthenticationOptions> context)
    {
        context.Response.StatusCode = StatusCodes.Status403Forbidden;
        context.Response.ContentType = "text/plain; charset=utf-8";
        return context.Response.WriteAsync("Administrator access is required.");
    }
}
