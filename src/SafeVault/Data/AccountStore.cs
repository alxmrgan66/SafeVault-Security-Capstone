using Microsoft.Data.Sqlite;
using SafeVault.Security;

namespace SafeVault.Data;

public sealed record Account(long Id, string Username, string Email, string DisplayName, string Role);
public sealed record Credentials(Account Account, string PasswordHash);

public sealed class AccountStore
{
    private readonly string databasePath;
    private readonly string connectionString;

    public AccountStore(string databasePath)
    {
        this.databasePath = Path.GetFullPath(databasePath);
        connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = this.databasePath,
            ForeignKeys = true,
            Pooling = false,
            DefaultTimeout = 5
        }.ToString();
    }

    public void Initialize()
    {
        Directory.CreateDirectory(Path.GetDirectoryName(databasePath)!);
        using var schema = typeof(AccountStore).Assembly.GetManifestResourceStream("SafeVault.DatabaseSchema")
            ?? throw new InvalidOperationException("Database schema is missing.");
        using var reader = new StreamReader(schema);
        using var connection = OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = reader.ReadToEnd();
        command.ExecuteNonQuery();
    }

    public bool CreateAccount(Registration registration, string passwordHash, string role)
    {
        using var connection = OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = """
            INSERT INTO Users (Username, Email, DisplayName, PasswordHash, Role)
            VALUES ($username, $email, $displayName, $passwordHash, $role)
            ON CONFLICT DO NOTHING
            """;
        command.Parameters.AddWithValue("$username", registration.Username);
        command.Parameters.AddWithValue("$email", registration.Email);
        command.Parameters.AddWithValue("$displayName", registration.DisplayName);
        command.Parameters.AddWithValue("$passwordHash", passwordHash);
        command.Parameters.AddWithValue("$role", role);
        return command.ExecuteNonQuery() == 1;
    }

    public Credentials? FindCredentials(string username)
    {
        using var connection = OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT UserID, Username, Email, DisplayName, Role, PasswordHash
            FROM Users
            WHERE Username = $username
            """;
        command.Parameters.AddWithValue("$username", username);
        using var reader = command.ExecuteReader();
        return reader.Read() ? new Credentials(ReadAccount(reader), reader.GetString(5)) : null;
    }

    public IReadOnlyList<Account> SearchAccounts(string displayName)
    {
        using var connection = OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT UserID, Username, Email, DisplayName, Role
            FROM Users
            WHERE instr(lower(DisplayName), lower($displayName)) > 0
            ORDER BY Username
            LIMIT 100
            """;
        command.Parameters.Add("$displayName", SqliteType.Text).Value = displayName;
        using var reader = command.ExecuteReader();
        var accounts = new List<Account>();
        while (reader.Read())
        {
            accounts.Add(ReadAccount(reader));
        }
        return accounts;
    }

    public void StartSession(long userId, string tokenHash, DateTimeOffset expiry)
    {
        using var connection = OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = """
            INSERT INTO Sessions (UserID, TokenHash, ExpiresAt)
            VALUES ($userId, $tokenHash, $expiresAt)
            ON CONFLICT (UserID) DO UPDATE SET
                TokenHash = excluded.TokenHash,
                ExpiresAt = excluded.ExpiresAt
            """;
        command.Parameters.AddWithValue("$userId", userId);
        command.Parameters.AddWithValue("$tokenHash", tokenHash);
        command.Parameters.AddWithValue("$expiresAt", expiry.ToUnixTimeSeconds());
        command.ExecuteNonQuery();
    }

    public Account? FindSession(string tokenHash, DateTimeOffset now)
    {
        using var connection = OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT u.UserID, u.Username, u.Email, u.DisplayName, u.Role
            FROM Sessions s JOIN Users u ON u.UserID = s.UserID
            WHERE s.TokenHash = $tokenHash AND s.ExpiresAt > $now
            """;
        command.Parameters.AddWithValue("$tokenHash", tokenHash);
        command.Parameters.AddWithValue("$now", now.ToUnixTimeSeconds());
        using var reader = command.ExecuteReader();
        return reader.Read() ? ReadAccount(reader) : null;
    }

    public void EndSession(string tokenHash)
    {
        using var connection = OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = "DELETE FROM Sessions WHERE TokenHash = $tokenHash";
        command.Parameters.AddWithValue("$tokenHash", tokenHash);
        command.ExecuteNonQuery();
    }

    private SqliteConnection OpenConnection()
    {
        var connection = new SqliteConnection(connectionString);
        try
        {
            connection.Open();
            return connection;
        }
        catch
        {
            connection.Dispose();
            throw;
        }
    }

    private static Account ReadAccount(SqliteDataReader reader) =>
        new(reader.GetInt64(0), reader.GetString(1), reader.GetString(2), reader.GetString(3), reader.GetString(4));
}
