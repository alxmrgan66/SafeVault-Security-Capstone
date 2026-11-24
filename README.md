# SafeVault

SafeVault is a C# web application for the Microsoft Security and Authentication capstone. It uses ASP.NET Core Razor Pages, SQLite, bcrypt, and NUnit. The app includes registration, login, an account profile, and an administrator dashboard. It follows the C# and NUnit test scaffold shown in Activity 1.

## Build and run

Install the [.NET 10 SDK](https://dotnet.microsoft.com/en-us/download/dotnet/10.0). Extract the project and run the commands from the `SafeVault` directory.

```bash
dotnet test Tests/SafeVault.Tests.csproj -c Release
dotnet run --project src/SafeVault
```

Open <http://127.0.0.1:5059/>. The app is configured for local review using fictional accounts. Use **Create an account** to register and sign in as a regular user. The SQLite database is created in `data/` under the application's content root. To select a different database file, set `SafeVault__DatabasePath` to its absolute path.

## Administrator access

Create the demo administrator from a local terminal. Use the same database configuration as for the web app. For Bash, run the following from the project directory.

```bash
read -rsp 'Choose an administrator password of at least 12 characters: ' safevault_admin_password
printf '\n'
SAFEVAULT_ADMIN_PASSWORD="$safevault_admin_password" dotnet run --project src/SafeVault -- create-admin admin admin@example.test
unset safevault_admin_password
```

Sign in as `admin` with the password you chose. The regular registration form assigns the `user` role. A regular user can see their profile and receives HTTP `403` on `/Admin`. The administrator can search the account list by display name. The app revalidates the session and role from SQLite on each protected request. Signing out revokes the session.

## Activity evidence

| Activity | Implementation | Verification |
| --- | --- | --- |
| 1. Secure code | [AccountValidation.cs](src/SafeVault/Security/AccountValidation.cs), [database.sql](src/SafeVault/Data/database.sql), and [AccountStore.cs](src/SafeVault/Data/AccountStore.cs) | [TestInputValidation.cs](Tests/TestInputValidation.cs) checks input limits, control characters, and literal search results with apostrophes, percent signs, and underscores. |
| 2. Authentication and RBAC | [Passwords.cs](src/SafeVault/Security/Passwords.cs), [AccountSessions.cs](src/SafeVault/Security/AccountSessions.cs), [Login](src/SafeVault/Pages/Login.cshtml.cs), and the [Admin dashboard](src/SafeVault/Pages/Admin/Index.cshtml.cs) | [TestAccessControl.cs](Tests/TestAccessControl.cs) checks invalid credentials, guest and member access, administrator access, and cookie removal after session revocation. |
| 3. SQL injection and XSS review | Parameter binding in [AccountStore.cs](src/SafeVault/Data/AccountStore.cs) and Razor output encoding on the [profile](src/SafeVault/Pages/Index.cshtml) and [dashboard](src/SafeVault/Pages/Admin/Index.cshtml) | NUnit verifies literal search results, encoded display names on both pages, and form antiforgery. |

All **23 NUnit cases passed**, with zero failures and zero skips, in a Release run on November 23, 2026 using .NET SDK 10.0.404. The [Microsoft Copilot activity record](COPILOT_WORKFLOW.md) documents the prompts, suggested changes, and observed test results.

The solution includes a [GitHub Actions workflow](.github/workflows/security-tests.yml) that runs NUnit and publishes the TRX report. This lets a reviewer open the Actions run after the repository is published.

## Submit for peer review

For Prompt 1, use the public GitHub repository URL for SafeVault. For Prompt 2, use [the security summary](SECURITY_SUMMARY.md). The public repository should contain the source, tests, and documentation. The local database, build outputs, and test output directories are excluded from Git.
