using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.Extensions.DependencyInjection.Extensions;
using SecureLab.Api.Data;

namespace SecureLab.Api.Tests;

public sealed class ProductionHardeningTests
{
    private sealed class Sink : ILoggerProvider
    {
        public ConcurrentQueue<string> Messages { get; } = new();
        public ILogger CreateLogger(string categoryName) => new Writer(this, categoryName);
        public void Dispose() { }
        private sealed class Writer(Sink sink, string category) : ILogger
        {
            public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
            public bool IsEnabled(LogLevel level) => category.EndsWith("SafeExceptionHandler",StringComparison.Ordinal);
            public void Log<TState>(LogLevel level, EventId id, TState state, Exception? error, Func<TState,Exception?,string> format)
            { if(IsEnabled(level)) sink.Messages.Enqueue(format(state,error)); }
        }
    }
    private static void Headers(HttpResponseMessage response)
    {
        Assert.Equal("nosniff",Assert.Single(response.Headers.GetValues("X-Content-Type-Options")));
        Assert.Equal("no-referrer",Assert.Single(response.Headers.GetValues("Referrer-Policy")));
        Assert.Contains("frame-ancestors 'none'",Assert.Single(response.Headers.GetValues("Content-Security-Policy")));
    }
    [Fact]
    public async Task Production_Authenticated200_Validation400_Resource404_AndStaticHeaders()
    {
        using var factory = new SecureLabApiFactory();
        using var production = factory.WithWebHostBuilder(b=>b.UseEnvironment("Production"));
        Assert.Equal("Production",production.Services.GetRequiredService<IHostEnvironment>().EnvironmentName);
        using var client=await production.LoginAsync("alice",Environment.GetEnvironmentVariable("SeedUsers__Password")!);
        foreach(var (route,status) in new[] { ("/",HttpStatusCode.OK), ("/api/me",HttpStatusCode.OK),
            ("/api/incidents?status=Unknown",HttpStatusCode.BadRequest),
            ("/api/incidents/99999999-9999-9999-9999-999999999999",HttpStatusCode.NotFound) })
        {
            using var response=await client.GetAsync(route);
            Assert.Equal(status,response.StatusCode); Headers(response);
            if(status==HttpStatusCode.BadRequest)
            {
                var body=await response.Content.ReadFromJsonAsync<JsonElement>();
                Assert.True(body.GetProperty("errors").TryGetProperty("status",out _));
            }
        }
        Assert.Equal(HttpStatusCode.NotFound,(await client.GetAsync("/openapi/v1.json")).StatusCode);
        using var token=await client.GetAsync("/api/auth/csrf-token");
        Assert.Equal(HttpStatusCode.OK,token.StatusCode);
        var cookie=Assert.Single(token.Headers.GetValues("Set-Cookie"),v=>v.StartsWith(".SecureLab.LR06.Antiforgery="));
        var attributes=cookie.Split(';').Skip(1).Select(v=>v.Trim().ToLowerInvariant());
        Assert.Contains("secure",attributes); Assert.Contains("httponly",attributes); Assert.Contains("samesite=strict",attributes);
    }

    [Fact]
    public async Task Production_Unexpected500_HasHeaders_SafeBody_AndMatchingInternalTrace()
    {
        using var factory=new SecureLabApiFactory(); var sink=new Sink();
        using var host=factory.WithWebHostBuilder(b=>{
            b.UseEnvironment("Production");
            b.ConfigureAppConfiguration((_,c)=>c.AddInMemoryCollection(new Dictionary<string,string?> {
                ["ConnectionStrings:SecureLab"]="Host=127.0.0.1;Port=54399;Database=securelab_lr06;Username=securelab;Password=unreachable-study-value;Timeout=1;Include Error Detail=false",
                ["Database:ApplyMigrationsOnStartup"]="false" }));
            b.ConfigureServices(s=>{
                s.AddSingleton<ILoggerProvider>(sink);
                // Test-host DB target, isolated from the environment of the real running API.
                s.RemoveAll<DbContextOptions<SecureLabDbContext>>();
                s.RemoveAll<IDbContextOptionsConfiguration<SecureLabDbContext>>();
                s.AddDbContext<SecureLabDbContext>(o=>o.UseNpgsql(
                    "Host=127.0.0.1;Port=54399;Database=securelab_lr06;Username=securelab;Password=unreachable-study-value;Timeout=1;Include Error Detail=false"));
            });
        });
        using var client=host.CreateClient(new() { AllowAutoRedirect=false });
        using var response=await client.PostAsJsonAsync("/api/auth/login",new { userName="alice",password="NotARealPassword1!" });
        Assert.Equal(HttpStatusCode.InternalServerError,response.StatusCode); Headers(response);
        Assert.Equal("application/problem+json",response.Content.Headers.ContentType?.MediaType);
        var text=await response.Content.ReadAsStringAsync(); var body=JsonSerializer.Deserialize<JsonElement>(text);
        var trace=body.GetProperty("traceId").GetString(); Assert.False(string.IsNullOrWhiteSpace(trace));
        Assert.Equal(new[]{"status","title","traceId","type"},body.EnumerateObject().Select(x=>x.Name).Order());
        Assert.Contains(sink.Messages,m=>m.Contains(trace!,StringComparison.Ordinal));
        foreach(var value in new[]{"Npgsql","SELECT ","Host=","Password=","NotARealPassword1!","unreachable-study-value","C:\\"})
            Assert.DoesNotContain(value,text,StringComparison.OrdinalIgnoreCase);
    }
}
