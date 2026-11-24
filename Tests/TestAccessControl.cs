using System.Net;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Builder;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.DependencyInjection;
using NUnit.Framework;
using SafeVault.Data;
using SafeVault.Security;

namespace SafeVault.Tests;

[TestFixture]
public sealed class TestAccessControl
{
    private const string SamplePassword = "Example lesson phrase 2026";
    private DirectoryInfo directory = null!;
    private WebApplication app = null!;
    private HttpClient client = null!;
    private CookieContainer cookies = null!;
    private AccountStore store = null!;
    private string DatabasePath => Path.Combine(directory.FullName, "test.sqlite");

    [SetUp]
    public async Task SetUp()
    {
        directory = Directory.CreateTempSubdirectory("safevault-http-");
        app = SafeVaultApplication.Build(
            ["--urls", "http://127.0.0.1:0", "--SafeVault:DatabasePath", DatabasePath],
            directory.FullName);
        store = app.Services.GetRequiredService<AccountStore>();
        store.Initialize();
        await app.StartAsync();
        cookies = new CookieContainer();
        client = new HttpClient(new HttpClientHandler
        {
            AllowAutoRedirect = false,
            CookieContainer = cookies
        })
        {
            BaseAddress = new Uri(app.Urls.Single())
        };
    }

    [TearDown]
    public async Task TearDown()
    {
        client?.Dispose();
        if (app is not null)
        {
            await app.StopAsync();
            await app.DisposeAsync();
        }
        directory?.Delete(recursive: true);
    }

    [Test]
    public async Task AnonymousAccessRedirectsToSignIn()
    {
        using var response = await client.GetAsync("/Admin");
        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Found));
        Assert.That(response.Headers.Location!.ToString(), Does.Contain("/Login"));
    }

    [Test]
    public async Task RegistrationCannotAssignAdministratorRole()
    {
        using var registration = await PostForm("/Register", "/Register", new()
        {
            ["Username"] = "member",
            ["Email"] = "member@example.test",
            ["DisplayName"] = "Course member",
            ["Password"] = SamplePassword,
            ["Role"] = "admin"
        });
        Assert.That(registration.StatusCode, Is.EqualTo(HttpStatusCode.Found));
        Assert.That(store.FindCredentials("member")?.Account.Role, Is.EqualTo("user"));
        using var login = await SignIn("member", SamplePassword);
        Assert.That(login.StatusCode, Is.EqualTo(HttpStatusCode.Found));
        using var profile = await client.GetAsync("/");
        Assert.That(profile.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        using var dashboard = await client.GetAsync("/Admin");
        Assert.That(dashboard.StatusCode, Is.EqualTo(HttpStatusCode.Forbidden));
    }

    [Test]
    public async Task LoginUsesTheSameMessageForUnknownUserAndWrongPassword()
    {
        AddAccount("member", "user", "Course member");
        using var wrong = await SignIn("member", "A different example phrase");
        using var unknown = await SignIn("nobody", "A different example phrase");
        var wrongHtml = await wrong.Content.ReadAsStringAsync();
        var unknownHtml = await unknown.Content.ReadAsStringAsync();
        Assert.Multiple(() =>
        {
            Assert.That(wrong.StatusCode, Is.EqualTo(HttpStatusCode.OK));
            Assert.That(unknown.StatusCode, Is.EqualTo(HttpStatusCode.OK));
            Assert.That(wrongHtml, Does.Contain("The username or password is incorrect."));
            Assert.That(unknownHtml, Does.Contain("The username or password is incorrect."));
            Assert.That(wrongHtml, Does.Not.Contain("A different example phrase"));
        });
    }

    [Test]
    public async Task TestForXssProtectionOnTheAdministratorDashboard()
    {
        AddAccount("admin", "admin", "Course administrator");
        AddAccount("member", "user", "<em>Sample name</em>");
        using var login = await SignIn("admin", SamplePassword);
        Assert.That(login.StatusCode, Is.EqualTo(HttpStatusCode.Found));
        var cookie = login.Headers.GetValues("Set-Cookie")
            .Single(value => value.StartsWith("SafeVault.Session=", StringComparison.Ordinal));

        using var dashboard = await client.GetAsync("/Admin?Name=Sample");
        var html = await dashboard.Content.ReadAsStringAsync();
        Assert.Multiple(() =>
        {
            Assert.That(dashboard.StatusCode, Is.EqualTo(HttpStatusCode.OK));
            Assert.That(html, Does.Contain("&lt;em&gt;Sample name&lt;/em&gt;"));
            Assert.That(html, Does.Not.Contain("<em>Sample name</em>"));
            Assert.That(html, Does.Not.Contain("Course administrator"));
            Assert.That(dashboard.Headers.GetValues("Content-Security-Policy").Single(), Does.Contain("frame-ancestors 'none'"));
            Assert.That(dashboard.Headers.GetValues("X-Content-Type-Options").Single(), Is.EqualTo("nosniff"));
            Assert.That(cookie.ToLowerInvariant(), Does.Contain("httponly").And.Contain("samesite=strict"));
        });
    }

    [Test]
    public async Task ProfileDisplayNameIsHtmlEncoded()
    {
        const string displayName = "<b>Training User</b>";
        using var registration = await PostForm("/Register", "/Register", new()
        {
            ["Username"] = "member",
            ["Email"] = "member@example.test",
            ["DisplayName"] = displayName,
            ["Password"] = SamplePassword
        });
        Assert.That(registration.StatusCode, Is.EqualTo(HttpStatusCode.Found));
        using var login = await SignIn("member", SamplePassword);
        Assert.That(login.StatusCode, Is.EqualTo(HttpStatusCode.Found));

        using var profile = await client.GetAsync("/");
        var html = await profile.Content.ReadAsStringAsync();
        Assert.Multiple(() =>
        {
            Assert.That(profile.StatusCode, Is.EqualTo(HttpStatusCode.OK));
            Assert.That(html, Does.Contain("&lt;b&gt;Training User&lt;/b&gt;"));
            Assert.That(html, Does.Not.Contain(displayName));
        });
    }

    [Test]
    public async Task FormPostRequiresAntiforgeryToken()
    {
        using var page = await client.GetAsync("/Register");
        Assert.That(page.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        using var form = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["Username"] = "member",
            ["Email"] = "member@example.test",
            ["DisplayName"] = "Course member",
            ["Password"] = SamplePassword
        });
        using var response = await client.PostAsync("/Register", form);
        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
        Assert.That(store.FindCredentials("member"), Is.Null);
    }

    [Test]
    public async Task SignOutRevokesAccess()
    {
        AddAccount("member", "user", "Course member");
        using var login = await SignIn("member", SamplePassword);
        Assert.That(login.StatusCode, Is.EqualTo(HttpStatusCode.Found));
        using var logout = await PostForm("/", "/?handler=SignOut", new());
        Assert.That(logout.StatusCode, Is.EqualTo(HttpStatusCode.Found));
        using var profile = await client.GetAsync("/");
        Assert.That(profile.StatusCode, Is.EqualTo(HttpStatusCode.Found));
        Assert.That(profile.Headers.Location!.ToString(), Does.Contain("/Login"));
    }

    [Test]
    public async Task RevokedAdministratorSessionIsDeniedAndClearsCookie()
    {
        AddAccount("admin", "admin", "Course administrator");
        using var login = await SignIn("admin", SamplePassword);
        Assert.That(login.StatusCode, Is.EqualTo(HttpStatusCode.Found));
        using var before = await client.GetAsync("/Admin");
        Assert.That(before.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        Assert.That(cookies.GetCookies(client.BaseAddress!)["SafeVault.Session"], Is.Not.Null);

        var admin = store.FindCredentials("admin")!.Account;
        var connectionString = new SqliteConnectionStringBuilder { DataSource = DatabasePath, Pooling = false };
        using (var connection = new SqliteConnection(connectionString.ToString()))
        {
            connection.Open();
            using var command = connection.CreateCommand();
            command.CommandText = "DELETE FROM Sessions WHERE UserID = $userId";
            command.Parameters.AddWithValue("$userId", admin.Id);
            Assert.That(command.ExecuteNonQuery(), Is.EqualTo(1));
        }

        using var after = await client.GetAsync("/Admin");
        var cookieRemoved = cookies.GetCookies(client.BaseAddress!)["SafeVault.Session"] is null;
        Assert.Multiple(() =>
        {
            Assert.That(after.StatusCode, Is.EqualTo(HttpStatusCode.Found));
            Assert.That(after.Headers.Location?.ToString(), Does.Contain("/Login"));
            Assert.That(cookieRemoved, Is.True, "The browser should remove the revoked session cookie.");
        });
    }

    private void AddAccount(string username, string role, string displayName)
    {
        var registration = new Registration(username, $"{username}@example.test", displayName, SamplePassword);
        Assert.That(store.CreateAccount(registration, Passwords.Hash(SamplePassword), role), Is.True);
    }

    private Task<HttpResponseMessage> SignIn(string username, string password) =>
        PostForm("/Login", "/Login", new() { ["Username"] = username, ["Password"] = password });

    private async Task<HttpResponseMessage> PostForm(string formPath, string postPath, Dictionary<string, string> values)
    {
        using var page = await client.GetAsync(formPath);
        Assert.That(page.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        var html = await page.Content.ReadAsStringAsync();
        var token = Regex.Match(html,
            """<input\b(?=[^>]*\bname="__RequestVerificationToken")(?=[^>]*\bvalue="([^"]+)")[^>]*>""",
            RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1));
        Assert.That(token.Success, Is.True, "The form must supply an antiforgery token.");
        values["__RequestVerificationToken"] = WebUtility.HtmlDecode(token.Groups[1].Value);
        using var content = new FormUrlEncodedContent(values);
        return await client.PostAsync(postPath, content);
    }

}
