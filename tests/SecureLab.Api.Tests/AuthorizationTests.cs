using System.Net;
using System.Net.Http.Json;
using System.Text.Json.Nodes;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using SecureLab.Api.Data;
using SecureLab.Api.Data.Entities;
using SecureLab.Api.Presentation.Contracts;

namespace SecureLab.Api.Tests;

public sealed class AuthorizationTests : IAsyncLifetime
{
    private readonly SecureLabApiFactory factory = new();
    private HttpClient alice = null!, bob = null!, morgan = null!, admin = null!;
    private readonly List<Guid> created = [];
    public async Task InitializeAsync()
    {
        var password = Environment.GetEnvironmentVariable("SeedUsers__Password")!;
        alice = await factory.LoginAsync("alice", password);
        bob = await factory.LoginAsync("bob", password);
        morgan = await factory.LoginAsync("morgan", password);
        admin = await factory.LoginAsync("admin", password);
        foreach (var client in new[] { alice, bob, morgan, admin }) await client.UseAntiforgeryTokenAsync();
    }
    public async Task DisposeAsync()
    {
        await using var scope = factory.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SecureLabDbContext>();
        await db.Incidents.Where(x => created.Contains(x.Id)).ExecuteDeleteAsync();
        alice.Dispose(); bob.Dispose(); morgan.Dispose(); admin.Dispose();
        await factory.DisposeAsync();
    }
    private async Task<Guid> CreateAsync(HttpClient client)
    {
        using var response = await client.PostAsJsonAsync("/api/incidents", new
        {
            title = "LR04-" + Guid.NewGuid(), description = "Synthetic test incident content.",
            severity = "Low", occurredAtUtc = DateTimeOffset.UtcNow.AddMinutes(-1)
        });
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        var dto = (await response.Content.ReadFromJsonAsync<CreatedIncidentResponse>())!;
        created.Add(dto.Id);
        return dto.Id;
    }
    private async Task<string> SnapshotAsync(Guid id)
    {
        await using var scope = factory.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SecureLabDbContext>();
        var row = await db.Incidents.AsNoTracking().Where(x => x.Id == id).Select(x => new
        { x.Id, x.Title, x.Description, x.Status, x.Severity, x.OwnerUserId, x.UpdatedAtUtc,
          History = x.StatusHistory.Count(), Comments = x.Comments.Count() }).SingleOrDefaultAsync();
        return System.Text.Json.JsonSerializer.Serialize(row);
    }

    [Fact]
    public async Task A01_Anonymous_AllProtectedOperations_Return401WithoutRedirect()
    {
        using var client = factory.CreateClient(new() { AllowAutoRedirect = false });
        foreach (var (method, path) in new[] {
            (HttpMethod.Get, "/api/incidents"),
            (HttpMethod.Get, $"/api/incidents/{DbSeeder.AliceIncidentId}"),
            (HttpMethod.Put, $"/api/incidents/{DbSeeder.AliceIncidentId}"),
            (HttpMethod.Delete, $"/api/incidents/{DbSeeder.AliceIncidentId}"),
            (HttpMethod.Post, $"/api/incidents/{DbSeeder.AliceIncidentId}/triage"),
            (HttpMethod.Get, "/api/incident-comments/30000000-0000-0000-0000-000000000003") })
        {
            using var request = new HttpRequestMessage(method, path);
            if (method == HttpMethod.Put) request.Content = JsonContent.Create(new { title = "x", description = "y" });
            using var response = await client.SendAsync(request);
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
            Assert.Null(response.Headers.Location);
            Assert.DoesNotContain("<!doctype", await response.Content.ReadAsStringAsync(), StringComparison.OrdinalIgnoreCase);
        }
    }

    [Fact]
    public async Task A02_A03_A03R_Details_UseVerifiedOwnerOrAnalyst()
    {
        using var own = await alice.GetAsync($"/api/incidents/{DbSeeder.AliceIncidentId}");
        Assert.Equal(HttpStatusCode.OK, own.StatusCode);
        var dto = (await own.Content.ReadFromJsonAsync<IncidentDetailsResponse>())!;
        Assert.Equal(DbSeeder.AliceIncidentId, dto.Id);
        using var other = await alice.GetAsync($"/api/incidents/{DbSeeder.BobIncidentId}");
        Assert.Equal(HttpStatusCode.NotFound, other.StatusCode);
        Assert.DoesNotContain("РќРµРІС–РґРѕРјР° СЃРїСЂРѕР±Р° РІС…РѕРґСѓ", await other.Content.ReadAsStringAsync());
        using var reverse = await bob.GetAsync($"/api/incidents/{DbSeeder.AliceIncidentId}");
        Assert.Equal(HttpStatusCode.NotFound, reverse.StatusCode);
        using var analyst = await morgan.GetAsync($"/api/incidents/{DbSeeder.AliceIncidentId}");
        Assert.Equal(HttpStatusCode.OK, analyst.StatusCode);
    }

    [Fact]
    public async Task A04_ForeignUpdateAndDelete_DoNotChangeAnyState()
    {
        var id = await CreateAsync(bob);
        var before = await SnapshotAsync(id);
        using var update = await alice.PutAsJsonAsync($"/api/incidents/{id}", new { title = "forged", description = "forged" });
        Assert.Equal(HttpStatusCode.NotFound, update.StatusCode);
        Assert.Equal(before, await SnapshotAsync(id));
        using var delete = await alice.DeleteAsync($"/api/incidents/{id}");
        Assert.Equal(HttpStatusCode.NotFound, delete.StatusCode);
        Assert.Equal(before, await SnapshotAsync(id));
    }

    [Fact]
    public async Task A05_List_IsScopedBeforeMaterialization_AndAnalystCanReadBothOwners()
    {
        var list = (await alice.GetFromJsonAsync<List<IncidentListItemResponse>>("/api/incidents"))!;
        Assert.Equal(new[] { DbSeeder.AliceIncidentId, DbSeeder.SafeTextIncidentId,
            Guid.Parse("20000000-0000-0000-0000-000000000005") }.Order(), list.Select(x => x.Id).Order());
        var all = (await morgan.GetFromJsonAsync<List<IncidentListItemResponse>>("/api/incidents"))!;
        Assert.Contains(all, x => x.Id == DbSeeder.AliceIncidentId);
        Assert.Contains(all, x => x.Id == DbSeeder.BobIncidentId);
    }

    [Fact]
    public async Task A06_ReporterCannotTriage_EvenWithForgedRoleAndOwner()
    {
        var id = await CreateAsync(alice);
        var before = await SnapshotAsync(id);
        using var denied = await alice.PostAsJsonAsync($"/api/incidents/{id}/triage",
            new { role = "Analyst", ownerUserId = DbSeeder.MorganId, status = "Triaged", isTransitionAllowed = true });
        Assert.Equal(HttpStatusCode.Forbidden, denied.StatusCode);
        Assert.Equal(before, await SnapshotAsync(id));
    }

    [Fact]
    public async Task A07_AnalystOnlyNewToTriaged_WithServerHistory_AndNoContentOrDeleteRights()
    {
        var id = await CreateAsync(alice);
        using var allowed = await morgan.PostAsync($"/api/incidents/{id}/triage", null);
        Assert.Equal(HttpStatusCode.NoContent, allowed.StatusCode);
        await using (var scope = factory.Services.CreateAsyncScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<SecureLabDbContext>();
            Assert.Equal(IncidentStatus.Triaged, (await db.Incidents.FindAsync(id))!.Status);
            var history = await db.IncidentStatusHistory.SingleAsync(x => x.IncidentId == id);
            Assert.Equal(DbSeeder.MorganId, history.ChangedByUserId);
            Assert.Equal(IncidentStatus.New, history.OldStatus);
            Assert.Equal(IncidentStatus.Triaged, history.NewStatus);
        }
        var before = await SnapshotAsync(id);
        using var again = await morgan.PostAsync($"/api/incidents/{id}/triage", null);
        using var update = await morgan.PutAsJsonAsync($"/api/incidents/{id}", new { title = "forged", description = "forged" });
        using var delete = await morgan.DeleteAsync($"/api/incidents/{id}");
        Assert.Equal(HttpStatusCode.Forbidden, again.StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, update.StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, delete.StatusCode);
        Assert.Equal(before, await SnapshotAsync(id));
    }

    [Fact]
    public async Task A08a_UpdateChangesOnlyContent_AndOwnerCanDeleteNew()
    {
        var id = await CreateAsync(alice);
        var title = "Updated-" + id;
        using var update = await alice.PutAsJsonAsync($"/api/incidents/{id}", new {
            title = " " + title + " ", description = " Updated synthetic content. ",
            ownerUserId = DbSeeder.BobId, role = "Administrator", status = "Closed", severity = "Critical",
            updatedAtUtc = "2000-01-01T00:00:00Z" });
        Assert.Equal(HttpStatusCode.NoContent, update.StatusCode);
        await using (var scope = factory.Services.CreateAsyncScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<SecureLabDbContext>();
            var row = (await db.Incidents.FindAsync(id))!;
            Assert.Equal(title, row.Title);
            Assert.Equal("Updated synthetic content.", row.Description);
            Assert.Equal(DbSeeder.AliceId, row.OwnerUserId);
            Assert.Equal(IncidentStatus.New, row.Status);
            Assert.Equal(IncidentSeverity.Low, row.Severity);
            Assert.True(row.UpdatedAtUtc > DateTimeOffset.UtcNow.AddMinutes(-1));
            var roles = await db.UserRoles.Where(x => x.UserId == DbSeeder.AliceId)
                .Join(db.Roles, x => x.RoleId, r => r.Id, (x,r) => r.Name).ToListAsync();
            Assert.Equal(new[] { "Reporter" }, roles);
        }
        using var delete = await alice.DeleteAsync($"/api/incidents/{id}");
        Assert.Equal(HttpStatusCode.NoContent, delete.StatusCode);
        Assert.Equal("null", await SnapshotAsync(id));
    }

    [Fact]
    public async Task OwnerCannotDeleteNonNew_AndAdministratorHasNoImplicitOverride()
    {
        var before = await SnapshotAsync(DbSeeder.AliceIncidentId);
        using var own = await alice.DeleteAsync($"/api/incidents/{DbSeeder.AliceIncidentId}");
        Assert.Equal(HttpStatusCode.Forbidden, own.StatusCode);
        using var adminRead = await admin.GetAsync($"/api/incidents/{DbSeeder.AliceIncidentId}");
        using var adminTriage = await admin.PostAsync($"/api/incidents/{DbSeeder.AliceIncidentId}/triage", null);
        Assert.Equal(HttpStatusCode.NotFound, adminRead.StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, adminTriage.StatusCode);
        Assert.Empty((await admin.GetFromJsonAsync<List<IncidentListItemResponse>>("/api/incidents"))!);
        Assert.Equal(before, await SnapshotAsync(DbSeeder.AliceIncidentId));
    }

    [Theory]
    [InlineData("GET")]
    [InlineData("PUT")]
    [InlineData("DELETE")]
    [InlineData("POST")]
    public async Task A10_ForeignAndUnknown_HaveSameProblemExceptTrace(string method)
    {
        async Task<(string?, JsonObject)> Problem(Guid id)
        {
            using var request = new HttpRequestMessage(new HttpMethod(method), $"/api/incidents/{id}" + (method == "POST" ? "/triage" : ""));
            if (method == "PUT") request.Content = JsonContent.Create(new { title = "x", description = "y" });
            using var response = await alice.SendAsync(request);
            Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
            var body = (await response.Content.ReadFromJsonAsync<JsonObject>())!;
            Assert.True(body.Remove("traceId"));
            return (response.Content.Headers.ContentType?.ToString(), body);
        }
        var foreign = await Problem(DbSeeder.BobIncidentId);
        var unknown = await Problem(Guid.NewGuid());
        Assert.Equal(unknown.Item1, foreign.Item1);
        Assert.True(JsonNode.DeepEquals(unknown.Item2, foreign.Item2));
    }

    [Fact]
    public async Task A12_ChildChecksParentAndInternalVisibility_OnDirectAndDetailsPaths()
    {
        var internalId = Guid.Parse("30000000-0000-0000-0000-000000000003");
        foreach (var id in new[] { internalId, Guid.Parse("30000000-0000-0000-0000-000000000002"), Guid.NewGuid() })
        {
            using var response = await alice.GetAsync($"/api/incident-comments/{id}");
            Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
            Assert.DoesNotContain("Text", await response.Content.ReadAsStringAsync(), StringComparison.OrdinalIgnoreCase);
        }
        var own = (await alice.GetFromJsonAsync<IncidentDetailsResponse>($"/api/incidents/{DbSeeder.AliceIncidentId}"))!;
        Assert.DoesNotContain(own.Comments, x => x.Id == internalId);
        using var ownComment = await alice.GetAsync("/api/incident-comments/30000000-0000-0000-0000-000000000001");
        Assert.Equal(HttpStatusCode.OK, ownComment.StatusCode);
        var analysis = (await morgan.GetFromJsonAsync<IncidentDetailsResponse>($"/api/incidents/{DbSeeder.AliceIncidentId}"))!;
        Assert.Contains(analysis.Comments, x => x.Id == internalId);
        using var analyst = await morgan.GetAsync($"/api/incident-comments/{internalId}");
        Assert.Equal(HttpStatusCode.OK, analyst.StatusCode);
    }
}
