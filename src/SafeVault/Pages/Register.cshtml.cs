using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.RateLimiting;
using SafeVault.Data;
using SafeVault.Security;

namespace SafeVault.Pages;

[EnableRateLimiting("account-forms")]
public sealed class RegisterModel(AccountStore store) : PageModel
{
    [BindProperty]
    public string? Username { get; set; }

    [BindProperty]
    public string? Email { get; set; }

    [BindProperty]
    public string? DisplayName { get; set; }

    [BindProperty]
    public string? Password { get; set; }

    public IActionResult OnPost()
    {
        if (!ModelState.IsValid)
        {
            return Page();
        }

        try
        {
            var registration = AccountValidation.ValidateRegistration(Username, Email, DisplayName, Password);
            if (store.CreateAccount(registration, Passwords.Hash(registration.Password), "user"))
            {
                return RedirectToPage("/Login", new { registered = true });
            }
            ModelState.AddModelError("", "That username or email is already registered.");
        }
        catch (ValidationException error)
        {
            ModelState.AddModelError("", error.Message);
        }
        return Page();
    }
}
