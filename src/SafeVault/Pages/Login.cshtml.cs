using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.RateLimiting;
using SafeVault.Data;
using SafeVault.Security;

namespace SafeVault.Pages;

[EnableRateLimiting("account-forms")]
public sealed class LoginModel(AccountStore store, AccountSessions sessions) : PageModel
{
    [BindProperty]
    public string? Username { get; set; }

    [BindProperty]
    public string? Password { get; set; }

    [BindProperty(SupportsGet = true)]
    public bool Registered { get; set; }

    public async Task<IActionResult> OnPostAsync()
    {
        if (!ModelState.IsValid)
        {
            return Page();
        }

        try
        {
            var login = AccountValidation.ValidateLogin(Username, Password);
            var credentials = store.FindCredentials(login.Username);
            if (Passwords.Verify(login.Password, credentials?.PasswordHash) && credentials is not null)
            {
                await sessions.SignInAsync(HttpContext, credentials.Account);
                return RedirectToPage("/Index");
            }
        }
        catch (ValidationException)
        {
            // Keep the same public error for malformed credentials and a failed lookup.
        }
        ModelState.AddModelError("", "The username or password is incorrect.");
        return Page();
    }
}
