using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SafeVault.Data;
using SafeVault.Security;

namespace SafeVault.Pages.Admin;

[Authorize(Roles = "admin")]
public sealed class IndexModel(AccountStore store) : PageModel
{
    [BindProperty(SupportsGet = true)]
    public string? Name { get; set; }

    public IReadOnlyList<Account> Accounts { get; private set; } = [];

    public void OnGet()
    {
        if (!ModelState.IsValid)
        {
            return;
        }
        try
        {
            Accounts = store.SearchAccounts(AccountValidation.ValidateSearch(Name));
        }
        catch (ValidationException error)
        {
            ModelState.AddModelError("", error.Message);
        }
    }
}
