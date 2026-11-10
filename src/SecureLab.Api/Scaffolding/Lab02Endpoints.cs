using Microsoft.EntityFrameworkCore;
using SecureLab.Api.Security;
using System.Security.Claims;
using SecureLab.Api.Data;
using SecureLab.Api.Data.Entities;
using SecureLab.Api.Presentation.Contracts;

namespace SecureLab.Api.Scaffolding;

// Навчальний старт ЛР 02. Запускати лише з локальними штучними даними.
public static class Lab02Endpoints
{
    public static void MapLab02Endpoints(this WebApplication app)
    {
        app.MapGet("/api/incidents/search", async (string? q, string? sortBy, SecureLabDbContext db, CancellationToken ct) =>
        {
            if (sortBy is not (null or "" or "createdAtUtc" or "severity" or "status"))
                return Results.ValidationProblem(new Dictionary<string, string[]>
                {
                    ["sortBy"] = ["Допустимі значення: createdAtUtc, severity, status."]
                });

            // SQL-параметр захищає структуру; escaping забезпечує буквальний підрядок ILIKE.
            var literal = (q ?? "").Replace("\\", "\\\\").Replace("%", "\\%").Replace("_", "\\_");
            var pattern = "%" + literal + "%";
            var query = db.Incidents.AsNoTracking().Where(row =>
                EF.Functions.ILike(row.Title, pattern, "\\")
                || EF.Functions.ILike(row.Description, pattern, "\\"));

            var ordered = sortBy switch
            {
                "severity" => query.OrderBy(row => row.Severity == IncidentSeverity.Critical ? 0
                    : row.Severity == IncidentSeverity.High ? 1
                    : row.Severity == IncidentSeverity.Medium ? 2 : 3),
                "status" => query.OrderBy(row => row.Status == IncidentStatus.New ? 0
                    : row.Status == IncidentStatus.Triaged ? 1
                    : row.Status == IncidentStatus.InProgress ? 2
                    : row.Status == IncidentStatus.Resolved ? 3 : 4),
                _ => query.OrderByDescending(row => row.CreatedAtUtc)
            };
            var rows = await ordered.ThenBy(row => row.Id).Take(50)
                .Select(row => new IncidentSearchResponse(row.Id, row.Title, row.Description,
                    row.Severity.ToString(), row.Status.ToString(), row.CreatedAtUtc))
                .ToListAsync(ct);
            return Results.Ok(rows);
        }).RequireRateLimiting(Lab03Identity.SearchPolicy);
        app.MapPost("/api/incidents", async (CreateIncidentRequest request, HttpContext context, SecureLabDbContext db, CancellationToken ct) =>
        {
            var now = DateTimeOffset.UtcNow;
            var errors = new Dictionary<string, string[]>();
            var title = request.Title?.Trim() ?? "";
            var description = request.Description?.Trim() ?? "";

            if (title.Length == 0 || request.Title!.Length > 160)
                errors["title"] = ["Заголовок обов'язковий і не може перевищувати 160 символів до обрізання пробілів."];
            if (description.Length == 0 || request.Description!.Length > 4000)
                errors["description"] = ["Опис обов'язковий і не може перевищувати 4000 символів до обрізання пробілів."];

            var validSeverity = Enum.TryParse<IncidentSeverity>(request.Severity, true, out var severity)
                && Enum.IsDefined(severity);
            if (!validSeverity)
                errors["severity"] = ["Допустимі значення: Low, Medium, High, Critical."];
            if (request.OccurredAtUtc is null || request.OccurredAtUtc > now.AddMinutes(5))
                errors["occurredAtUtc"] = ["Час події обов'язковий і не може бути більш ніж на 5 хвилин у майбутньому."];
            if (validSeverity && severity is IncidentSeverity.High or IncidentSeverity.Critical
                && description.Length < 40)
                errors["description"] = ["Для High або Critical опис після обрізання пробілів має містити щонайменше 40 символів."];

            if (errors.Count > 0)
                return Results.ValidationProblem(errors);

            if (!Guid.TryParse(context.User.FindFirstValue(ClaimTypes.NameIdentifier), out var ownerId))
                return Results.Problem(statusCode: StatusCodes.Status500InternalServerError);

            // Навчальна перевірка конфлікту; не гарантує унікальність при одночасних POST.
            if (await db.Incidents.AnyAsync(row => row.Title == title
                && (row.Status == IncidentStatus.New || row.Status == IncidentStatus.Triaged
                    || row.Status == IncidentStatus.InProgress || row.Status == IncidentStatus.Resolved), ct))
                return Results.Problem(statusCode: StatusCodes.Status409Conflict,
                    title: "Інцидент уже існує",
                    detail: "Незакритий інцидент із таким заголовком уже зареєстровано.");

            var incident = new Incident
            {
                Id = Guid.NewGuid(), OwnerUserId = ownerId,
                Title = title, Description = description, Severity = severity,
                Status = IncidentStatus.New, OccurredAtUtc = request.OccurredAtUtc!.Value.ToUniversalTime(),
                CreatedAtUtc = now, UpdatedAtUtc = now
            };
            db.Incidents.Add(incident);
            await db.SaveChangesAsync(ct);
            return Results.Created($"/api/incidents/{incident.Id}", new CreatedIncidentResponse(
                incident.Id, incident.Title, incident.Description, incident.Severity.ToString(),
                incident.Status.ToString(), incident.OccurredAtUtc, incident.CreatedAtUtc, incident.UpdatedAtUtc));
        }).RequireAuthorization().AddEndpointFilter<CsrfProtection>();
    }
}

