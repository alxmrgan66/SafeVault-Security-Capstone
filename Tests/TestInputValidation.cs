using System.ComponentModel.DataAnnotations;
using NUnit.Framework;
using SafeVault.Data;
using SafeVault.Security;

namespace SafeVault.Tests;

[TestFixture]
public sealed class TestInputValidation
{
    private const string SamplePassword = "Example lesson phrase 2026";

    [Test]
    public void NormalizesRegistrationFields()
    {
        var account = AccountValidation.ValidateRegistration(
            "  LEARNER  ", "  LEARNER@example.test ", "  Casey O'Connor  ", SamplePassword);

        Assert.Multiple(() =>
        {
            Assert.That(account.Username, Is.EqualTo("learner"));
            Assert.That(account.Email, Is.EqualTo("learner@example.test"));
            Assert.That(account.DisplayName, Is.EqualTo("Casey O'Connor"));
            Assert.That(account.Password, Is.EqualTo(SamplePassword));
        });
    }

    [TestCase("u", "learner@example.test", "Learner", SamplePassword)]
    [TestCase("user name", "learner@example.test", "Learner", SamplePassword)]
    [TestCase("learner", "missing-at-sign", "Learner", SamplePassword)]
    [TestCase("learner", "learner@example.test", "", SamplePassword)]
    [TestCase("learner", "learner@example.test", "Title\u0000break", SamplePassword)]
    [TestCase("\tlearner", "learner@example.test", "Learner", SamplePassword)]
    [TestCase("learner", "learner@example.test\r", "Learner", SamplePassword)]
    [TestCase("learner", "learner@example.test", "\tLearner", SamplePassword)]
    [TestCase("learner", "learner@example.test", "Learner", "short")]
    public void RejectsInvalidRegistration(string username, string email, string displayName, string password)
    {
        Assert.That(() => AccountValidation.ValidateRegistration(username, email, displayName, password),
            Throws.TypeOf<ValidationException>());
    }

    [Test]
    public void RejectsPasswordsOverBcryptByteLimit()
    {
        Assert.That(() => AccountValidation.ValidateLogin("learner", new string('é', 37)),
            Throws.TypeOf<ValidationException>());
    }

    [TestCase("\tCasey")]
    [TestCase("Casey\r")]
    public void SearchRejectsControlCharactersAtTheEdges(string displayName)
    {
        Assert.That(() => AccountValidation.ValidateSearch(displayName), Throws.TypeOf<ValidationException>());
    }

    [Test]
    public void TestForSqlInjectionProtection()
    {
        var folder = Directory.CreateTempSubdirectory("safevault-sql-");
        try
        {
            var store = new AccountStore(Path.Combine(folder.FullName, "test.sqlite"));
            store.Initialize();
            var first = new Registration("first", "first@example.test", "Casey O'Connor (QA%_Team)", SamplePassword);
            var second = new Registration("second", "second@example.test", "Casey OConnor (QAXTeam)", SamplePassword);
            store.CreateAccount(first, Passwords.Hash(first.Password), "user");
            store.CreateAccount(second, Passwords.Hash(second.Password), "user");

            Assert.Multiple(() =>
            {
                Assert.That(store.SearchAccounts("O'Connor (QA%_Team)").Select(account => account.Username),
                    Is.EqualTo(new[] { "first" }));
                Assert.That(store.SearchAccounts("%").Select(account => account.Username), Is.EqualTo(new[] { "first" }));
                Assert.That(store.SearchAccounts("_").Select(account => account.Username), Is.EqualTo(new[] { "first" }));
                Assert.That(store.FindCredentials("first")?.Account.DisplayName, Is.EqualTo(first.DisplayName));
                Assert.That(store.SearchAccounts(""), Has.Count.EqualTo(2));
            });
        }
        finally
        {
            folder.Delete(recursive: true);
        }
    }

    [Test]
    public void PasswordsHaveDifferentSaltsAndVerifyCorrectly()
    {
        var first = Passwords.Hash(SamplePassword);
        var second = Passwords.Hash(SamplePassword);
        Assert.Multiple(() =>
        {
            Assert.That(first, Is.Not.EqualTo(second));
            Assert.That(first, Is.Not.EqualTo(SamplePassword));
            Assert.That(Passwords.Verify(SamplePassword, first), Is.True);
            Assert.That(Passwords.Verify("A different example phrase", first), Is.False);
            Assert.That(Passwords.Verify(SamplePassword, null), Is.False);
        });
    }
}
