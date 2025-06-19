using Microsoft.AspNetCore.Mvc;
using System;
using System.Data.SQLite;
public class SessionManager
{
    public static string CreateSession(Int64 UserID)
    {
        using (SQLiteConnection connection = DatabaseConnector.CreateNewConnection())
        {
            string SessionID;

            do
            {
                SessionID = Guid.NewGuid().ToString();
            } while (SessionIDExists(SessionID, connection));

            Int64 validUntil = DateTimeOffset.UtcNow.ToUnixTimeSeconds() + 3600;

            string insertSql = "INSERT INTO Session (SessionID, UserID, ValidUntil, LoginTime) VALUES (@SessionID, @UserID, @ValidUntil, @LoginTime)";
            using (SQLiteCommand cmd = new SQLiteCommand(insertSql, connection))
            {
                cmd.Parameters.AddWithValue("@SessionID", SessionID);
                cmd.Parameters.AddWithValue("@UserID", UserID);
                cmd.Parameters.AddWithValue("@ValidUntil", validUntil);
                cmd.Parameters.AddWithValue("@LoginTime", DateTimeOffset.UtcNow.ToUnixTimeSeconds());
                cmd.ExecuteNonQuery();
            }
            return SessionID;
        }
    }

    private static bool SessionIDExists(string SessionID, SQLiteConnection connection)
    {
        string selectSql = "SELECT COUNT(*) FROM Session WHERE SessionID = @SessionID";

        using (SQLiteCommand cmd = new SQLiteCommand(selectSql, connection))
        {
            cmd.Parameters.AddWithValue("@SessionID", SessionID);

            try
            {
                object result = cmd.ExecuteScalar();
                if (result != null && Convert.ToInt64(result) > 0)
                    return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine("Exception occurred: " + ex.Message);
                // Log the exception for further analysis
            }
        }
        return false;
    }

    public static string InvalidateAllSessions(Int64 UserID)
    {
        using (SQLiteConnection connection = DatabaseConnector.CreateNewConnection())
        {
            string deleteSql = "DELETE FROM Session WHERE UserID = @UserID";
            using (SQLiteCommand cmd = new SQLiteCommand(deleteSql, connection))
            {
                cmd.Parameters.AddWithValue("@UserID", UserID);
                cmd.ExecuteNonQuery();
            }
        }
        return "All sessions invalidated for UserID: " + UserID;
    }

    public static string InvalidateSession(string SessionID)
    {
        using (SQLiteConnection connection = DatabaseConnector.CreateNewConnection())
        {
            string deleteSql = "DELETE FROM Session WHERE SessionID = @SessionID";
            using (SQLiteCommand cmd = new SQLiteCommand(deleteSql, connection))
            {
                cmd.Parameters.AddWithValue("@SessionID", SessionID);
                cmd.ExecuteNonQuery();
            }
        }
        return "Session invalidated for SessionID: " + SessionID;
    }

    public static Int64 GetUserID(string? SessionID)
    {
        using (SQLiteConnection connection = DatabaseConnector.CreateNewConnection())
        {
            string selectSql = "SELECT UserID FROM Session WHERE SessionID = @SessionID AND ValidUntil > @CurrentTime";

            using (SQLiteCommand cmd = new SQLiteCommand(selectSql, connection))
            {
                cmd.Parameters.AddWithValue("@SessionID", SessionID);
                cmd.Parameters.AddWithValue("@CurrentTime", DateTimeOffset.UtcNow.ToUnixTimeSeconds());

                try
                {
                    object result = cmd.ExecuteScalar();
                    if (result != null)
                        return Convert.ToInt64(result);
                }
                catch (Exception ex)
                {
                    Console.WriteLine("Exception occurred: " + ex.Message);
                    // Log the exception for further analysis
                }
            }
        }
        return -1;
    }

    public static Int64 ValidateSession(string? sessionId)
    {
        if (string.IsNullOrEmpty(sessionId))
            throw new UnauthorizedAccessException("No session cookie");

        Int64 userID = SessionManager.GetUserID(sessionId);
        if (userID == -1)
            throw new UnauthorizedAccessException("Session invalid or expired");

        return userID;
    }
}