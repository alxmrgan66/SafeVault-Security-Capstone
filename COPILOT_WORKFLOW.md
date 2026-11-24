# Microsoft Copilot activity record

On November 23, 2026, ChatGPT used Microsoft Copilot in the browser on the learner's behalf. Copilot generated code and NUnit examples for the three activities. ChatGPT adapted the examples to SafeVault and ran the tests.

| Activity | Copilot's contribution | Change and verification |
| --- | --- | --- |
| [1. Writing secure code](https://www.coursera.org/learn/security-and-authentication/assignment-submission/ZK9fr/activity-writing-secure-code-using-microsoft-copilot) | Identified that trimming could hide leading or trailing control characters. Suggested checking the original input and binding the search parameter as `SqliteType.Text`. | [AccountValidation.cs](src/SafeVault/Security/AccountValidation.cs) checks the original username, email, display name, and search term. [AccountStore.cs](src/SafeVault/Data/AccountStore.cs) explicitly binds `$displayName` as text. [TestInputValidation.cs](Tests/TestInputValidation.cs) checks field validation and literal search matching for apostrophes, percent signs, and underscores. |
| [2. Authentication and authorization](https://www.coursera.org/learn/security-and-authentication/assignment-submission/gxB7k/activity-implementing-authentication-and-authorization-using-microsoft-copilot) | Suggested signing out the cookie scheme when the SQLite session is rejected and testing access after server-side revocation. The follow-up recommended omitting forced cookie renewal with fixed session expiry. | [AccountSessions.cs](src/SafeVault/Security/AccountSessions.cs) rejects the principal and clears the cookie for the current scheme. [TestAccessControl.cs](Tests/TestAccessControl.cs) verifies that a revoked administrator session redirects to login and that the client removes the cookie. It also checks guest, member, and administrator permissions. |
| [3. Security debugging](https://www.coursera.org/learn/security-and-authentication/assignment-submission/yeVZH/activity-debugging-and-resolving-security-issues-using-microsoft-copilot) | Reviewed the parameterized search and Razor output. Generated examples for testing literal search matches and HTML encoding, with a follow-up on excluding similar names from search results. | The search regression checks for the exact matching account. The new profile test registers a name with harmless markup, signs in, and checks the HTML response for encoded text. The existing dashboard test checks the same encoding control there. |

## Verification

With the new tests and the original application code, five cases exposed acceptance of edge control characters and one exposed the stale cookie after revocation. The SQL and Razor encoding tests passed in that run. After the changes, all **23 NUnit cases passed** with zero failures and zero skips.

```bash
dotnet test Tests/SafeVault.Tests.csproj -c Release --disable-build-servers --verbosity minimal
```

## Prompts sent to Microsoft Copilot

### Initial review

```text
For SafeVault, a defensive C#/.NET 10 classroom app (ASP.NET Core Razor Pages, Microsoft.Data.Sqlite, NUnit), generate small code changes and NUnit tests for three activities. All data is fictional.

1. Input validation and SQL. AccountValidation.ValidateLogin normalizes a username with username?.Trim().ToLowerInvariant() before an ASCII allowlist. Registration email and display name and the search term are trimmed before checking control characters. Generate a minimal C# refinement that checks raw input for control characters and still permits ordinary surrounding spaces. AccountStore searches with fixed WHERE instr(lower(DisplayName), lower($displayName)) > 0 and AddWithValue. Show bound C# SQL and an NUnit check that ordinary names with apostrophes, percent signs, or underscores are matched literally.

2. Authentication and RBAC. VaultCookieEvents.ValidatePrincipal checks a hashed cookie session ID against an expiring SQLite record. If no session exists it calls RejectPrincipal. If valid it replaces the principal with database roles. The admin page has [Authorize(Roles = "admin")]. Generate a small C# improvement for rejected or revoked sessions and a concrete NUnit integration assertion for server-side denial after revocation. Keep role checks on the server.

3. Debugging SQL/XSS. Review binding and Razor rendering via @account.DisplayName in the admin list and @User.FindFirstValue("safevault_display_name") on the user profile. Generate an NUnit HTTP regression test for HTML-encoded profile display text using harmless formatting markup as a fixture.

Use three short numbered sections, with actionable C# and NUnit examples. Distinguish risks you see from protections already present. Focus on defensive code and harmless test data.
```

### Follow-up

```text
Please refine the patch for this actual SafeVault structure. In AccountStore.SearchAccounts the static query selects UserID, Username, Email, DisplayName, Role FROM Users WHERE instr(lower(DisplayName), lower($displayName)) > 0 ORDER BY Username LIMIT 100. Show how to bind $displayName explicitly as SqliteType.Text. For the NUnit check add similar ordinary names that lack the literal percent or underscore, so the test detects overmatching. In VaultCookieEvents use context.Scheme.Name to clear the rejected cookie. The SQLite session already has a fixed expiry and valid requests rebuild the principal; explain whether to omit ShouldRenew = true. Give small snippets and no additional dependencies.
```

## Implementation references

- [Microsoft.Data.Sqlite parameters](https://learn.microsoft.com/en-us/dotnet/standard/data/sqlite/parameters)
- [ASP.NET Core cookie authentication](https://learn.microsoft.com/en-us/aspnet/core/security/authentication/cookie?view=aspnetcore-10.0)
- [Razor output encoding](https://learn.microsoft.com/en-us/aspnet/core/security/cross-site-scripting?view=aspnetcore-10.0)
