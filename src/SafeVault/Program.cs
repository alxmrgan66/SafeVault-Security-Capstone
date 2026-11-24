using System.ComponentModel.DataAnnotations;
using SafeVault;
using SafeVault.Data;
using SafeVault.Security;

var provisionAdmin = args.Length > 0 && args[0] == "create-admin";
await using var app = SafeVaultApplication.Build(provisionAdmin ? Array.Empty<string>() : args);
var store = app.Services.GetRequiredService<AccountStore>();
if (provisionAdmin)
{
    if (args.Length != 3)
    {
        Console.Error.WriteLine("Usage: create-admin USERNAME EMAIL");
        Environment.ExitCode = 1;
        return;
    }
    try
    {
        var registration = AccountValidation.ValidateRegistration(args[1], args[2], args[1],
            Environment.GetEnvironmentVariable("SAFEVAULT_ADMIN_PASSWORD"));
        store.Initialize();
        if (store.CreateAccount(registration, Passwords.Hash(registration.Password), "admin"))
        {
            Console.WriteLine($"Administrator created ({registration.Username}).");
        }
        else
        {
            Console.Error.WriteLine("That username or email is already registered.");
            Environment.ExitCode = 1;
        }
    }
    catch (ValidationException error)
    {
        Console.Error.WriteLine(error.Message);
        Environment.ExitCode = 1;
    }
    return;
}

store.Initialize();
await app.RunAsync();
