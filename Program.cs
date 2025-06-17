using Microsoft.AspNetCore.Http.HttpResults;
using System.Data.SQLite;


var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

app.MapControllers();

app.UseStaticFiles();

app.MapGet("/", () => Results.Redirect("/index.html"));
SQLiteConnection connection = DatabaseConnector.Db();
SQLiteCommand command = connection.CreateCommand();
command.CommandText = "PRAGMA foreign_keys = ON;" +
    "CREATE TABLE IF NOT EXISTS `User` (" +
    "`UserID` INTEGER NOT NULL PRIMARY KEY, " +
    "`Username` TEXT NOT NULL, " +
    "`PasswordHash` TEXT NOT NULL, " +
    "`PasswordSalt` TEXT NOT NULL);" +

    "CREATE TABLE IF NOT EXISTS `Session` (" +
    "`SessionID` TEXT NOT NULL PRIMARY KEY, " +
    "`UserID` INTEGER NOT NULL, " +
    "`ValidUntil` DATETIME NOT NULL, " +
    "`LoginTime` DATETIME NOT NULL);";

command.ExecuteNonQuery();

command.Dispose();

app.Run();
