using Microsoft.AspNetCore.Mvc;
using System.Data.SQLite;

[ApiController]
[Route("[controller]/[action]")]
public class UserController : Controller
{

    [HttpPost]
    public IActionResult Create([FromForm] string username, [FromForm] string password)
    {
        using (var connection = DatabaseConnector.CreateNewConnection())
        {
            // Ellenőrizzük, hogy a felhasználónév már létezik-e
            string checkUserSql = "SELECT COUNT(*) FROM User WHERE Username = @Username";
            using (var checkCmd = new SQLiteCommand(checkUserSql, connection))
            {
                checkCmd.Parameters.AddWithValue("@Username", username);
                long count = (long)checkCmd.ExecuteScalar();
                if (count > 0)
                {
                    return Conflict("Username already exists.");
                }
            }

            // Jelszó hashelése és mentése
            string salt = PasswordManager.GenerateSalt();
            string hashedPassword = PasswordManager.GeneratePasswordHash(password, salt);

            string insertSql = "INSERT INTO User (Username, PasswordHash, PasswordSalt) VALUES (@Username, @PasswordHash, @PasswordSalt)";
            using (SQLiteCommand cmd = new SQLiteCommand(insertSql, connection))
            {
                cmd.Parameters.AddWithValue("@Username", username);
                cmd.Parameters.AddWithValue("@PasswordHash", hashedPassword);
                cmd.Parameters.AddWithValue("@PasswordSalt", salt);
                cmd.ExecuteNonQuery();
            }
        }

        return Ok("User created successfully");
    }

    [HttpPost]
    public IActionResult Login([FromForm] string username, [FromForm] string password)
    {
        Int64 userID = -1;

        // Csak az olvasásra használjuk a DB kapcsolatot, majd bezárjuk
        using (SQLiteConnection connection = DatabaseConnector.CreateNewConnection())
        {
            // Megnézzük, hogy be van-e jelentkezve már az éppen bejelentkezni kívánó felhasználó
            string selectSql = $"SELECT UserID FROM User WHERE Username = '{username}'"; 
            using (SQLiteCommand cmd = new SQLiteCommand(selectSql, connection))
            {
                using (SQLiteDataReader reader = cmd.ExecuteReader())
                {
                    if (reader.Read())
                    {
                        userID = Convert.ToInt64(reader["UserID"]);
                    }
                }
            }
            if (userID == -1)
            {
                selectSql = $"SELECT UserID, SessionID FROM Session WHERE UserID = '{userID}'";
                using (SQLiteCommand cmd = new SQLiteCommand(selectSql, connection))
                {
                    using (SQLiteDataReader reader = cmd.ExecuteReader())
                    {
                        if (reader.Read())
                        {
                            string? SessionIDValue = reader["SessionID"]?.ToString();
                            if (!string.IsNullOrEmpty(SessionIDValue))
                            {
                                SessionManager.InvalidateSession(SessionIDValue);
                            }
                        }
                    }
                }
            }
            // Jelszó ellenőrzése
                selectSql = $"SELECT UserID, PasswordHash, PasswordSalt FROM User WHERE Username = '{username}'";
            using (SQLiteCommand cmd = new SQLiteCommand(selectSql, connection))
            {
                using (SQLiteDataReader reader = cmd.ExecuteReader())
                {
                    if (reader.Read())
                    {
                        string? storedPasswordHash = reader["PasswordHash"].ToString();
                        string? storedSalt = reader["PasswordSalt"].ToString();

                        if (!string.IsNullOrEmpty(storedPasswordHash) && !string.IsNullOrEmpty(storedSalt) &&
                            PasswordManager.Verify(password, storedSalt, storedPasswordHash))
                        {
                            userID = Convert.ToInt64(reader["UserID"]);
                        }
                        else
                        {
                            userID = -1;
                        }
                    }
                }
            }
        }
        if (userID == -1)
        {
            return Unauthorized("Helytelen felhasználónév vagy jelszó!");
        }
        // Itt már nincs megnyitva másik kapcsolat, mehet az írás
        SessionManager.InvalidateAllSessions(userID);
        string SessionID = SessionManager.CreateSession(userID);

        Response.Cookies.Append("id", SessionID, new CookieOptions
        {
            HttpOnly = true,
            Secure = true,
            SameSite = SameSiteMode.Strict,
            Expires = DateTime.UtcNow.AddHours(1)
        });

        return Ok(new { message = "Bejelentkezés sikeres!"});
    }

    [HttpPost]
    public IActionResult Logout()
    {
        var currentSessionID = Request.Cookies["id"];
        if (string.IsNullOrEmpty(currentSessionID))
        {
            return new UnauthorizedResult();
        }
        SessionManager.InvalidateSession(currentSessionID);
        Response.Cookies.Delete("id");
        return Ok("Kijelentkezés sikeres!");
    }

    static public bool IsLoggedIn(string SessionID)
    {
        Int64 userID = SessionManager.GetUserID(SessionID);
        return userID != -1;
    }

    [HttpGet]
    public IActionResult GetUser()
    {
        try
        {
            var sessionId = Request.Cookies["id"];
            Int64 userID = SessionManager.ValidateSession(sessionId);
            return Json(userID);
        }
        catch (UnauthorizedAccessException)
        {
            Response.Cookies.Delete("id");
            return Unauthorized("Munkamenet lejárt, vagy érvénytelen.");
        }
    }

    [HttpGet]
    public IActionResult CheckSession()
    {
        var sessionId = Request.Cookies["id"];
        if (string.IsNullOrEmpty(sessionId))
        {
            return Json(new { userID = -1, username = (string?)null });
        }
        Int64 userID = SessionManager.GetUserID(sessionId);
        if (userID == -1)
        {
            return Json(new { userID = -1, username = (string?)null });
        }

        string? username = null;
        using (var connection = DatabaseConnector.CreateNewConnection())
        {
            string selectSql = "SELECT Username FROM User WHERE UserID = @UserID";
            using (var cmd = new SQLiteCommand(selectSql, connection))
            {
                cmd.Parameters.AddWithValue("@UserID", userID);
                using (var reader = cmd.ExecuteReader())
                {
                    if (reader.Read())
                    {
                        username = reader["Username"].ToString();
                    }
                }
            }
        }

        return Json(new { userID, username });
    }
}