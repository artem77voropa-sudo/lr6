using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using SecureLab.Api.Data;
using SecureLab.Api.Security;

namespace SecureLab.Api.Tests;

public sealed class CsrfSecurityTests : IAsyncLifetime
{
    private readonly SecureLabApiFactory factory = new();
    private readonly List<Guid> created = [];
    private HttpClient alice = null!;
    private static string Password => Environment.GetEnvironmentVariable("SeedUsers__Password")!;
    public async Task InitializeAsync()
    {
        alice = await factory.LoginAsync("alice", Password);
        await alice.UseAntiforgeryTokenAsync();
    }
    public async Task DisposeAsync()
    {
        await using var scope = factory.Services.CreateAsyncScope();
        await scope.ServiceProvider.GetRequiredService<SecureLabDbContext>().Incidents
            .Where(x => created.Contains(x.Id)).ExecuteDeleteAsync();
        alice.Dispose(); await factory.DisposeAsync();
    }
    private static object Body(string title) => new { title, description = "Synthetic CSRF regression description.",
        severity = "Low", occurredAtUtc = "2026-09-01T10:00:00Z" };
    private async Task<Guid> CreateAsync(HttpClient client)
    {
        using var response = await client.PostAsJsonAsync("/api/incidents", Body("LR06-"+Guid.NewGuid()));
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        var row = await response.Content.ReadFromJsonAsync<JsonElement>();
        var id = row.GetProperty("id").GetGuid(); created.Add(id); return id;
    }

    [Theory]
    [InlineData("create", false)] [InlineData("create", true)]
    [InlineData("update", false)] [InlineData("update", true)]
    [InlineData("delete", false)] [InlineData("delete", true)]
    [InlineData("triage", false)] [InlineData("triage", true)]
    [InlineData("logout", false)] [InlineData("logout", true)]
    public async Task REG_CSRF01_AllMutations_RejectBadTokenWithoutStateChange_ThenAcceptValidPair(string operation, bool invalid)
    {
        var id = await CreateAsync(alice);
        using var other = operation == "triage" ? await factory.LoginAsync("morgan", Password) : null;
        var actor = other ?? alice;
        var before = await alice.GetStringAsync($"/api/incidents/{id}");
        var title = "LR06-csrf-new-"+Guid.NewGuid();
        var route = operation switch {
            "create" => "/api/incidents", "logout" => "/api/auth/logout",
            "triage" => $"/api/incidents/{id}/triage", _ => $"/api/incidents/{id}" };
        var method = operation switch { "update" => HttpMethod.Put, "delete" => HttpMethod.Delete, _ => HttpMethod.Post };
        actor.DefaultRequestHeaders.Remove(CsrfProtection.Header);
        if (invalid) actor.DefaultRequestHeaders.Add(CsrfProtection.Header, "synthetic-invalid-token");
        using var request = new HttpRequestMessage(method, route) { Content = JsonContent.Create(Body(title)) };
        using var denied = await actor.SendAsync(request);
        Assert.Equal(HttpStatusCode.BadRequest, denied.StatusCode);
        var problem = await denied.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal("csrf_validation_failed", problem.GetProperty("code").GetString());
        Assert.False(problem.TryGetProperty("errors", out _));
        Assert.Equal(before, await alice.GetStringAsync($"/api/incidents/{id}"));
        using var stillAuthenticated = await actor.GetAsync("/api/me");
        Assert.Equal(HttpStatusCode.OK, stillAuthenticated.StatusCode);
        await using var scope = factory.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SecureLabDbContext>();
        Assert.False(await db.Incidents.AnyAsync(x => x.Title == title));

        await actor.UseAntiforgeryTokenAsync();
        using var allowedRequest = new HttpRequestMessage(method, route) { Content = JsonContent.Create(Body(title)) };
        using var allowed = await actor.SendAsync(allowedRequest);
        Assert.Equal(operation == "create" ? HttpStatusCode.Created : HttpStatusCode.NoContent, allowed.StatusCode);
        if (operation == "create")
        {
            var row = await allowed.Content.ReadFromJsonAsync<JsonElement>();
            var newId = row.GetProperty("id").GetGuid(); created.Add(newId);
            Assert.Equal(title, (await alice.GetFromJsonAsync<JsonElement>($"/api/incidents/{newId}")).GetProperty("title").GetString());
        }
        else if (operation == "delete")
            Assert.Equal(HttpStatusCode.NotFound, (await alice.GetAsync($"/api/incidents/{id}")).StatusCode);
        else if (operation == "logout")
            Assert.Equal(HttpStatusCode.Unauthorized, (await actor.GetAsync("/api/me")).StatusCode);
        else
        {
            var after = await alice.GetFromJsonAsync<JsonElement>($"/api/incidents/{id}");
            Assert.Equal(operation == "triage" ? "Triaged" : title,
                after.GetProperty(operation == "triage" ? "status" : "title").GetString());
        }
    }

    [Fact]
    public async Task Token_FromPreviousPrincipal_IsRejectedAfterNewLogin()
    {
        using var logout = await alice.PostAsync("/api/auth/logout", null);
        Assert.Equal(HttpStatusCode.NoContent, logout.StatusCode);
        using var login = await alice.PostAsJsonAsync("/api/auth/login", new { userName="bob", password=Password });
        Assert.Equal(HttpStatusCode.NoContent, login.StatusCode);
        var title = "LR06-stale-"+Guid.NewGuid();
        using var stale = await alice.PostAsJsonAsync("/api/incidents", Body(title));
        Assert.Equal(HttpStatusCode.BadRequest, stale.StatusCode);
        await alice.UseAntiforgeryTokenAsync();
        await CreateAsync(alice);
    }

    [Fact]
    public async Task TokenRoute_IsAuthenticated_NoStore_AndNotCorsReadable()
    {
        using var anonymous = factory.CreateClient(new() { AllowAutoRedirect=false });
        Assert.Equal(HttpStatusCode.Unauthorized, (await anonymous.GetAsync(CsrfProtection.TokenRoute)).StatusCode);
        using var request = new HttpRequestMessage(HttpMethod.Get, CsrfProtection.TokenRoute);
        request.Headers.Add("Origin", "http://localhost:4173");
        using var response = await alice.SendAsync(request);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.True(response.Headers.CacheControl?.NoStore);
        Assert.False(response.Headers.Contains("Access-Control-Allow-Origin"));
    }
}
