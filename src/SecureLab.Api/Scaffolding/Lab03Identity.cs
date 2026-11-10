using System.ComponentModel.DataAnnotations;
using SecureLab.Api.Security;
using System.Security.Claims;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Identity;
using SecureLab.Api.Data;
using SecureLab.Api.Data.Entities;
using SecureLab.Api.Presentation.Contracts;

namespace SecureLab.Api.Scaffolding;

public static class Lab03Identity
{
    public const string LoginPolicy = "login";
    public const string SearchPolicy = "incident-search";

    public static void AddLab03Identity(this WebApplicationBuilder builder)
    {
        builder.Services.AddIdentity<ApplicationUser, IdentityRole<Guid>>(options =>
        {
            options.User.RequireUniqueEmail = true;
            options.Password.RequiredLength = 10;
        }).AddEntityFrameworkStores<SecureLabDbContext>().AddDefaultTokenProviders();
        builder.Services.AddAuthorization();
        builder.Services.ConfigureApplicationCookie(options =>
        {
            options.Cookie.Name = ".SecureLab.LR06.Identity";
            options.Cookie.HttpOnly = true;
            options.Cookie.SameSite = SameSiteMode.Lax;
            options.Cookie.SecurePolicy = builder.Environment.IsDevelopment()
                ? CookieSecurePolicy.SameAsRequest : CookieSecurePolicy.Always;
            options.Events.OnRedirectToLogin = context =>
            {
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                return Task.CompletedTask;
            };
            options.Events.OnRedirectToAccessDenied = context =>
            {
                context.Response.StatusCode = StatusCodes.Status403Forbidden;
                return Task.CompletedTask;
            };
        });
        builder.Services.AddRateLimiter(options =>
        {
            options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
            options.AddPolicy(LoginPolicy, context => RateLimitPartition.GetFixedWindowLimiter(
                context.Connection.RemoteIpAddress?.ToString() ?? "unknown", _ => new()
                {
                    PermitLimit = 10, Window = TimeSpan.FromMinutes(1), QueueLimit = 0
                }));
            options.AddPolicy(SearchPolicy, context => RateLimitPartition.GetFixedWindowLimiter(
                context.User.Identity?.IsAuthenticated == true
                    && Guid.TryParse(context.User.FindFirstValue(ClaimTypes.NameIdentifier), out var subject)
                    ? "user:" + subject.ToString("D") : "ip:" + (context.Connection.RemoteIpAddress?.ToString() ?? "unknown"),
                _ => new() { PermitLimit = 20, Window = TimeSpan.FromSeconds(10), QueueLimit = 0 }));
            options.OnRejected = async (context, cancellationToken) =>
            {
                var search = context.HttpContext.Request.Path == "/api/incidents/search";
                var logger = context.HttpContext.RequestServices.GetRequiredService<ILoggerFactory>()
                    .CreateLogger(search ? "SecureLab.RateLimit" : "SecureLab.Authentication");
                LogEvent(logger, context.HttpContext, search ? "search" : "login", "rate-limited");
                if (context.Lease.TryGetMetadata(MetadataName.RetryAfter, out var retryAfter))
                    context.HttpContext.Response.Headers.RetryAfter =
                        Math.Ceiling(retryAfter.TotalSeconds).ToString(System.Globalization.CultureInfo.InvariantCulture);
                await Results.Problem(statusCode: 429, title: search ? "Забагато пошукових запитів" : "Забагато спроб входу",
                    detail: search ? "Повторіть пошук після завершення 10-секундного вікна." : "Зачекайте до завершення хвилинного вікна та повторіть вхід.")
                    .ExecuteAsync(context.HttpContext);
            };
        });
    }

    public static void MapLab03Identity(this WebApplication app)
    {
        app.MapPost("/api/auth/register", async (RegistrationInput input, UserManager<ApplicationUser> users,
            HttpContext context, ILoggerFactory logs) =>
        {
            var userName = input.UserName?.Trim() ?? "";
            var email = input.Email?.Trim() ?? "";
            var displayName = input.DisplayName?.Trim() ?? "";
            var errors = new Dictionary<string, string[]>();
            // Межі перевіряються до збереження. Пароль не обрізається й не нормалізується.
            if (userName.Length == 0 || (input.UserName?.Length ?? 0) > 256
                || userName.Any(c => !"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._@+".Contains(c)))
                errors["userName"] = ["Ім’я обов’язкове, до 256 символів; латинські літери, цифри та -._@+."];
            if (email.Length == 0 || (input.Email?.Length ?? 0) > 256 || !new EmailAddressAttribute().IsValid(email))
                errors["email"] = ["Укажіть коректний email довжиною до 256 символів."];
            if (displayName.Length == 0 || (input.DisplayName?.Length ?? 0) > 120 || displayName.Any(char.IsControl))
                errors["displayName"] = ["Ім’я для показу обов’язкове, до 120 символів, без керувальних символів."];
            if (string.IsNullOrEmpty(input.Password))
                errors["password"] = ["Пароль обов’язковий."];
            if (errors.Count > 0) return Results.ValidationProblem(errors);

            var user = new ApplicationUser
            {
                Id = Guid.NewGuid(), UserName = userName, Email = email, DisplayName = displayName
            };
            var result = await users.CreateAsync(user, input.Password!);
            var logger = logs.CreateLogger("SecureLab.Authentication");
            if (!result.Succeeded)
            {
                LogEvent(logger, context, "register", "rejected");
                if (result.Errors.Any(e => e.Code is "DuplicateUserName" or "DuplicateEmail"))
                    return Results.Problem(statusCode: 409, title: "Реєстрація недоступна",
                        detail: "Обліковий запис із такими реєстраційними даними вже існує.");
                // Не серіалізуємо Identity error.Description: він може містити введені значення.
                return Results.ValidationProblem(new Dictionary<string, string[]>
                {
                    ["registration"] = ["Перевірте поля. Пароль: від 10 символів, велика й мала латинські літери, цифра та спеціальний символ."]
                });
            }
            var role = await users.AddToRoleAsync(user, DbSeeder.ReporterRole);
            if (!role.Succeeded)
            {
                await users.DeleteAsync(user);
                return Results.Problem(statusCode: 500);
            }
            LogEvent(logger, context, "register", "success");
            return Results.Created("/api/me", new RegistrationResponse(user.Id, user.UserName!, user.DisplayName));
        });
        app.MapPost("/api/auth/login", async (LoginInput input, SignInManager<ApplicationUser> signIn,
            HttpContext context, ILoggerFactory logs) =>
        {
            var succeeded = false;
            if (!string.IsNullOrWhiteSpace(input.UserName) && !string.IsNullOrEmpty(input.Password))
                succeeded = (await signIn.PasswordSignInAsync(input.UserName, input.Password, false, false)).Succeeded;
            LogEvent(logs.CreateLogger("SecureLab.Authentication"), context, "login", succeeded ? "success" : "rejected");
            return succeeded ? Results.NoContent() : Results.Problem(statusCode: 401,
                title: "Не вдалося увійти", detail: "Перевірте ім’я користувача та пароль.");
        }).RequireRateLimiting(LoginPolicy);
        app.MapPost("/api/auth/logout", async (SignInManager<ApplicationUser> signIn,
            HttpContext context, ILoggerFactory logs) =>
        {
            await signIn.SignOutAsync();
            LogEvent(logs.CreateLogger("SecureLab.Authentication"), context, "logout", "success");
            return Results.NoContent();
        }).RequireAuthorization().AddEndpointFilter<CsrfProtection>();
        app.MapGet("/api/me", (HttpContext context) =>
        {
            if (!Guid.TryParse(context.User.FindFirstValue(ClaimTypes.NameIdentifier), out var id))
                return Results.Problem(statusCode: 500);
            return Results.Ok(new CurrentUserResponse(id,
                context.User.FindFirstValue(ClaimTypes.Name) ?? "",
                context.User.FindFirstValue(ClaimTypes.Role) ?? ""));
        }).RequireAuthorization();
        app.MapGet("/api/auth/session-check", () => Results.NoContent()).RequireAuthorization();
    }

    private static void LogEvent(ILogger logger, HttpContext context, string eventType, string result) =>
        logger.LogInformation("Auth event {EventType} at {UtcTime}: {Result}; trace {TraceId}",
            eventType, DateTimeOffset.UtcNow, result, context.TraceIdentifier);
}
