using System.Diagnostics;
using SecureLab.Api.Security;
using Microsoft.EntityFrameworkCore;
using SecureLab.Api.Application.Incidents;
using SecureLab.Api.Data;
using SecureLab.Api.Data.Entities;
using SecureLab.Api.Presentation.Contracts;

namespace SecureLab.Api.Presentation.Endpoints;

public static class IncidentMutationEndpoints
{
    public static IResult NotFound() => Results.Problem(statusCode: 404, title: "Інцидент не знайдено");
    private static IResult Forbidden() => Results.Problem(statusCode: 403, title: "Дію не дозволено");

    public static void MapIncidentMutationEndpoints(this IEndpointRouteBuilder endpoints)
    {
        var group = endpoints.MapGroup("/api/incidents").RequireAuthorization().WithTags("Incidents");
        group.MapPut("/{id:guid}", UpdateAsync).AddEndpointFilter<CsrfProtection>();
        group.MapDelete("/{id:guid}", DeleteAsync).AddEndpointFilter<CsrfProtection>();
        group.MapPost("/{id:guid}/triage", TriageAsync).AddEndpointFilter<CsrfProtection>();
        endpoints.MapGet("/api/incident-comments/{id:guid}", ReadCommentAsync).RequireAuthorization();
    }

    private static async Task<IResult> UpdateAsync(Guid id, UpdateIncidentRequest input,
        SecureLabDbContext db, IncidentAccess access, CancellationToken ct)
    {
        var row = await db.Incidents.SingleOrDefaultAsync(x => x.Id == id, ct);
        if (row is null || !access.CanRead(row)) return NotFound();
        if (!access.CanUpdate(row)) return Forbidden();
        var title = input.Title?.Trim() ?? "";
        var description = input.Description?.Trim() ?? "";
        var errors = new Dictionary<string, string[]>();
        if (title.Length == 0 || input.Title!.Length > 160) errors["title"] = ["Потрібно від 1 до 160 символів."];
        if (description.Length == 0 || input.Description!.Length > 4000) errors["description"] = ["Потрібно від 1 до 4000 символів."];
        if (row.Severity is IncidentSeverity.High or IncidentSeverity.Critical && description.Length < 40)
            errors["description"] = ["Для High/Critical потрібно щонайменше 40 символів."];
        if (errors.Count > 0) return Results.ValidationProblem(errors);
        if (row.Status != IncidentStatus.Closed && await db.Incidents.AnyAsync(x =>
            x.Id != id && x.Title == title && x.Status != IncidentStatus.Closed, ct))
            return Results.Problem(statusCode: 409, title: "Інцидент уже існує");
        row.Title = title;
        row.Description = description;
        row.UpdatedAtUtc = DateTimeOffset.UtcNow;
        await db.SaveChangesAsync(ct);
        return Results.NoContent();
    }

    private static async Task<IResult> DeleteAsync(Guid id, SecureLabDbContext db,
        IncidentAccess access, CancellationToken ct)
    {
        var row = await db.Incidents.SingleOrDefaultAsync(x => x.Id == id, ct);
        if (row is null || !access.CanRead(row)) return NotFound();
        if (!access.CanDelete(row)) return Forbidden();
        db.Incidents.Remove(row);
        await db.SaveChangesAsync(ct);
        return Results.NoContent();
    }

    private static async Task<IResult> TriageAsync(Guid id, SecureLabDbContext db, IncidentAccess access,
        HttpContext context, ILoggerFactory logs, CancellationToken ct)
    {
        var row = await db.Incidents.SingleOrDefaultAsync(x => x.Id == id, ct);
        if (row is null || !access.CanTriage(row))
        {
            logs.CreateLogger("SecureLab.Authorization").LogWarning(
                "{EventName} subject={SubjectId} action={Action} resource={ResourceId} result={Result} utc={UtcTime} trace={TraceId}",
                "authorization.denied", access.UserId, "incident.triage", id, "denied", DateTimeOffset.UtcNow,
                Activity.Current?.Id ?? context.TraceIdentifier);
            return row is null || !access.CanRead(row) ? NotFound() : Forbidden();
        }
        row.Status = IncidentStatus.Triaged;
        row.UpdatedAtUtc = DateTimeOffset.UtcNow;
        db.IncidentStatusHistory.Add(new IncidentStatusHistory
        {
            Id = Guid.NewGuid(), IncidentId = id, ChangedByUserId = access.UserId,
            OldStatus = IncidentStatus.New, NewStatus = IncidentStatus.Triaged,
            Note = "Первинна класифікація аналітиком.", CreatedAtUtc = row.UpdatedAtUtc
        });
        await db.SaveChangesAsync(ct);
        logs.CreateLogger("SecureLab.Authorization").LogInformation(
            "{EventName} subject={SubjectId} action={Action} resource={ResourceId} result={Result} utc={UtcTime} trace={TraceId}",
            "authorization.allowed", access.UserId, "incident.triage", id, "success", DateTimeOffset.UtcNow,
            Activity.Current?.Id ?? context.TraceIdentifier);
        return Results.NoContent();
    }

    private static async Task<IResult> ReadCommentAsync(Guid id, SecureLabDbContext db,
        IncidentAccess access, CancellationToken ct)
    {
        var comment = await db.IncidentComments.AsNoTracking().Include(x => x.Incident)
            .Include(x => x.Author).SingleOrDefaultAsync(x => x.Id == id, ct);
        if (comment is null || !access.CanReadComment(comment)) return NotFound();
        return Results.Ok(new IncidentCommentResponse(comment.Id, comment.Author.DisplayName,
            comment.Text, comment.CreatedAtUtc));
    }
}
