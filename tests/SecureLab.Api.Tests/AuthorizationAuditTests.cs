using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using SecureLab.Api.Data;

namespace SecureLab.Api.Tests;

public sealed class AuthorizationAuditTests
{
    [Fact]
    public async Task LR06_Triage_DeniedAndAllowed_AreAudited_AfterObservedState()
    {
        using var factory = new SecureLabApiFactory();
        var sink = new Sink();
        using var host = factory.WithWebHostBuilder(b => b.ConfigureServices(s => s.AddSingleton<ILoggerProvider>(sink)));
        var password = Environment.GetEnvironmentVariable("SeedUsers__Password")!;
        using var alice = await host.LoginAsync("alice", password);
        using var morgan = await host.LoginAsync("morgan", password);
        await alice.UseAntiforgeryTokenAsync(); await morgan.UseAntiforgeryTokenAsync();
        using var created = await alice.PostAsJsonAsync("/api/incidents", new { title="LR06-audit-"+Guid.NewGuid(),
            description="Synthetic audit transition",severity="Low",occurredAtUtc="2026-09-01T10:00:00Z" });
        Assert.Equal(HttpStatusCode.Created,created.StatusCode);
        var id=(await created.Content.ReadFromJsonAsync<JsonObject>())!["id"]!.GetValue<Guid>();
        try
        {
            using var denied=await alice.PostAsync($"/api/incidents/{id}/triage",null);
            Assert.Equal(HttpStatusCode.Forbidden,denied.StatusCode);
            Assert.Equal("New",(await alice.GetFromJsonAsync<JsonObject>($"/api/incidents/{id}"))!["status"]!.GetValue<string>());
            using var allowed=await morgan.PostAsync($"/api/incidents/{id}/triage",null);
            Assert.Equal(HttpStatusCode.NoContent,allowed.StatusCode);
            Assert.Equal("Triaged",(await alice.GetFromJsonAsync<JsonObject>($"/api/incidents/{id}"))!["status"]!.GetValue<string>());
            Assert.Equal(2,sink.Events.Count);
            var accepted=Assert.Single(sink.Events,e=>Equals(e["Result"],"success"));
            Assert.Equal(DbSeeder.MorganId,accepted["SubjectId"]);
            Assert.Equal(id,accepted["ResourceId"]);
            Assert.Equal("incident.triage",accepted["Action"]);
            Assert.NotNull(accepted["UtcTime"]); Assert.NotNull(accepted["TraceId"]);
            Assert.DoesNotContain(password,System.Text.Json.JsonSerializer.Serialize(sink.Events));
        }
        finally
        {
            await using var scope=host.Services.CreateAsyncScope();
            var db=scope.ServiceProvider.GetRequiredService<SecureLabDbContext>();
            await Microsoft.EntityFrameworkCore.EntityFrameworkQueryableExtensions.ExecuteDeleteAsync(db.Incidents.Where(x=>x.Id==id));
        }
    }

    private sealed class Sink : ILoggerProvider
    {
        public ConcurrentQueue<Dictionary<string, object?>> Events { get; } = new();
        public ILogger CreateLogger(string categoryName) => new Writer(this, categoryName);
        public void Dispose() { }
        private sealed class Writer(Sink sink, string category) : ILogger
        {
            public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
            public bool IsEnabled(LogLevel level) => category == "SecureLab.Authorization";
            public void Log<TState>(LogLevel level, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
            {
                if (IsEnabled(level) && state is IEnumerable<KeyValuePair<string, object?>> fields)
                    sink.Events.Enqueue(fields.ToDictionary(x => x.Key, x => x.Value));
            }
        }
    }

    [Fact]
    public async Task A09_DeniedTriage_HasOnlySafeAuditFields_AndMatchesResponseTrace()
    {
        using var factory = new SecureLabApiFactory();
        var sink = new Sink();
        using var host = factory.WithWebHostBuilder(b => b.ConfigureServices(s => s.AddSingleton<ILoggerProvider>(sink)));
        using var client = host.CreateClient(new() { BaseAddress = new Uri("https://localhost"), AllowAutoRedirect = false });
        var password = Environment.GetEnvironmentVariable("SeedUsers__Password")!;
        using var login = await client.PostAsJsonAsync("/api/auth/login", new { userName = "alice", password });
        Assert.Equal(HttpStatusCode.NoContent, login.StatusCode);
        await client.UseAntiforgeryTokenAsync();
        using var denied = await client.PostAsJsonAsync($"/api/incidents/{DbSeeder.AliceIncidentId}/triage", new { password = "never-log-this-body", role = "Analyst" });
        Assert.Equal(HttpStatusCode.Forbidden, denied.StatusCode);
        var body = (await denied.Content.ReadFromJsonAsync<JsonObject>())!;
        var entry = Assert.Single(sink.Events);
        Assert.Equal(new[] { "Action", "EventName", "ResourceId", "Result", "SubjectId", "TraceId", "UtcTime", "{OriginalFormat}" }, entry.Keys.Order(StringComparer.Ordinal));
        Assert.Equal("authorization.denied", entry["EventName"]);
        Assert.Equal(DbSeeder.AliceId, entry["SubjectId"]);
        Assert.Equal(DbSeeder.AliceIncidentId, entry["ResourceId"]);
        Assert.Equal("denied", entry["Result"]);
        Assert.Equal(body["traceId"]!.GetValue<string>(), entry["TraceId"]);
        var serialized = System.Text.Json.JsonSerializer.Serialize(entry);
        Assert.DoesNotContain(password, serialized);
        Assert.DoesNotContain("never-log-this-body", serialized);
        Assert.DoesNotContain("Cookie", serialized);
    }
}
