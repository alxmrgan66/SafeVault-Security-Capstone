using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SafeVault.Security;

namespace SafeVault.Pages;

[Authorize]
public sealed class IndexModel(AccountSessions sessions) : PageModel
{
    public async Task<IActionResult> OnPostSignOutAsync()
    {
        await sessions.SignOutAsync(HttpContext);
        return RedirectToPage("/Login");
    }
}
