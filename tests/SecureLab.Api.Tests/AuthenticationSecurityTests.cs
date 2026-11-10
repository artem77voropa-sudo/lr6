using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using SecureLab.Api.Data;
using SecureLab.Api.Presentation.Contracts;

namespace SecureLab.Api.Tests;

public sealed class AuthenticationSecurityTests(SecureLabApiFactory factory) : IClassFixture<SecureLabApiFactory>
{
    private static string Password => Environment.GetEnvironmentVariable("SeedUsers__Password")
        ?? throw new InvalidOperationException("Set local SeedUsers__Password outside Git.");

    [Theory]
    [InlineData("/api/me")]
    [InlineData("/api/incidents")]
    public async Task A01_Anonymous_Returns401WithoutRedirect(string route)
    {
        using var client = factory.CreateClient(new() { AllowAutoRedirect = false });
        client.DefaultRequestHeaders.Add("X-Demo-UserId", DbSeeder.BobId.ToString());
        using var response = route == "/api/me" ? await client.GetAsync(route)
            : await client.PostAsJsonAsync(route, IncidentBody("anonymous"));
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Null(response.Headers.Location);
        Assert.Empty(response.Headers.WwwAuthenticate);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
    }

    [Fact]
    public async Task A02_Login_ProfileComesFromPrincipal()
    {
        using var client = await factory.LoginAsync("alice", Password);
        using var response = await client.GetAsync("/api/me");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal(DbSeeder.AliceId, json.RootElement.GetProperty("id").GetGuid());
        Assert.Equal("alice", json.RootElement.GetProperty("userName").GetString());
        Assert.Equal(new[] { "id", "role", "userName" },
            json.RootElement.EnumerateObject().Select(p => p.Name).Order().ToArray());
    }

    [Fact]
    public async Task A03_ForgedHeader_DoesNotChangePrincipal()
    {
        using var client = await factory.LoginAsync("alice", Password);
        client.DefaultRequestHeaders.Add("X-Demo-UserId", DbSeeder.BobId.ToString());
        using var response = await client.GetAsync("/api/me");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal(DbSeeder.AliceId, json.RootElement.GetProperty("id").GetGuid());
    }

    private static Dictionary<string, object> IncidentBody(string title) => new()
    {
        ["title"] = title, ["description"] = "РЎРёРЅС‚РµС‚РёС‡РЅРёР№ РѕРїРёСЃ РґР»СЏ РїРµСЂРµРІС–СЂРєРё РІР»Р°СЃРЅРёРєР°.",
        ["severity"] = "Low", ["occurredAtUtc"] = "2026-09-01T10:00:00Z"
    };

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task A04_A05_BobCreates_OwnerAlwaysComesFromPrincipal(bool forgeOwner)
    {
        using var client = await factory.LoginAsync("bob", Password);
        await client.UseAntiforgeryTokenAsync();
        var title = $"LR03-owner-{Guid.NewGuid():N}";
        var body = IncidentBody(title);
        if (forgeOwner) body["ownerUserId"] = DbSeeder.AliceId;
        await using var scope = factory.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SecureLabDbContext>();
        try
        {
            using var response = await client.PostAsJsonAsync("/api/incidents", body);
            Assert.Equal(HttpStatusCode.Created, response.StatusCode);
            var created = await response.Content.ReadFromJsonAsync<CreatedIncidentResponse>();
            Assert.NotNull(created);
            var owner = await db.Incidents.Where(i => i.Id == created.Id).Select(i => i.OwnerUserId).SingleAsync();
            Assert.Equal(DbSeeder.BobId, owner);
        }
        finally { await db.Incidents.Where(i => i.Title == title).ExecuteDeleteAsync(); }
    }

    [Fact]
    public async Task A06_Logout_SameClientLosesAccess()
    {
        using var client = await factory.LoginAsync("alice", Password);
        using var before = await client.GetAsync("/api/me");
        Assert.Equal(HttpStatusCode.OK, before.StatusCode);
        await client.UseAntiforgeryTokenAsync();
        using var logout = await client.PostAsync("/api/auth/logout", null);
        Assert.Equal(HttpStatusCode.NoContent, logout.StatusCode);
        using var after = await client.GetAsync("/api/me");
        Assert.Equal(HttpStatusCode.Unauthorized, after.StatusCode);
        using var create = await client.PostAsJsonAsync("/api/incidents", IncidentBody("after-logout"));
        Assert.Equal(HttpStatusCode.Unauthorized, create.StatusCode);
    }

    [Fact]
    public async Task A07_UnknownUserAndWrongPassword_HaveSameSafeResponse()
    {
        using var client = factory.CreateClient();
        using var unknown = await client.PostAsJsonAsync("/api/auth/login",
            new { userName = $"absent-{Guid.NewGuid():N}", password = Password });
        using var wrong = await client.PostAsJsonAsync("/api/auth/login",
            new { userName = "alice", password = Password + "-wrong" });
        Assert.Equal(HttpStatusCode.Unauthorized, unknown.StatusCode);
        Assert.Equal(unknown.StatusCode, wrong.StatusCode);
        Assert.Equal("application/problem+json", unknown.Content.Headers.ContentType?.MediaType);
        Assert.Equal(unknown.Content.Headers.ContentType?.MediaType, wrong.Content.Headers.ContentType?.MediaType);
        using var first = JsonDocument.Parse(await unknown.Content.ReadAsStringAsync());
        using var second = JsonDocument.Parse(await wrong.Content.ReadAsStringAsync());
        foreach (var key in new[] { "type", "title", "status", "detail", "code", "message" })
        {
            var hasFirst = first.RootElement.TryGetProperty(key, out var a);
            var hasSecond = second.RootElement.TryGetProperty(key, out var b);
            Assert.Equal(hasFirst, hasSecond);
            if (hasFirst) Assert.Equal(a.ToString(), b.ToString());
        }
        foreach (var doc in new[] { first, second })
            Assert.All(doc.RootElement.EnumerateObject(), p =>
                Assert.Contains(p.Name, new[] { "type", "title", "status", "detail", "traceId" }));
    }
}
