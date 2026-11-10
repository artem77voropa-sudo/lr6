using System.Net;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace SecureLab.Api.Tests;

public sealed class CookieAndRateLimitTests(SecureLabApiFactory factory) : IClassFixture<SecureLabApiFactory>
{
    private static string Password => Environment.GetEnvironmentVariable("SeedUsers__Password")
        ?? throw new InvalidOperationException("Set local SeedUsers__Password outside Git.");

    [Theory]
    [InlineData("Development", "http", false)]
    [InlineData("Development", "https", true)]
    [InlineData("Production", "https", true)]
    public async Task CookieFlags_ActualResponseMatchesProfile(string environment, string scheme, bool secure)
    {
        using var host = factory.WithWebHostBuilder(b => b.UseEnvironment(environment));
        using var client = host.CreateClient(new() { BaseAddress = new Uri(scheme + "://localhost"), AllowAutoRedirect = false });
        using var response = await client.PostAsJsonAsync("/api/auth/login", new { userName = "alice", password = Password });
        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
        var cookies = response.Headers.GetValues("Set-Cookie").Where(v => v.StartsWith(".SecureLab.LR06.Identity=")).ToArray();
        Assert.True(cookies.Length == 1);
        var attributes = cookies[0].Split(';').Skip(1).Select(s => s.Trim().ToLowerInvariant()).ToArray();
        Assert.Contains("httponly", attributes);
        Assert.Contains("samesite=lax", attributes);
        Assert.Equal(secure, attributes.Contains("secure"));
        Assert.DoesNotContain(attributes, a => a.StartsWith("expires=") || a.StartsWith("max-age="));
        var options = host.Services.GetRequiredService<IOptionsMonitor<CookieAuthenticationOptions>>()
            .Get(IdentityConstants.ApplicationScheme);
        Assert.Equal(TimeSpan.FromDays(14), options.ExpireTimeSpan);
        Assert.True(options.SlidingExpiration);
    }

    [Fact]
    public async Task LoginLimit_TenPerMinute_SharedClients_ThenRecovers()
    {
        using var host = factory.WithWebHostBuilder(_ => { });
        using var first = host.CreateClient();
        using var second = host.CreateClient();
        for (var i = 0; i < 10; i++)
        {
            using var accepted = await first.PostAsJsonAsync("/api/auth/login", new { userName = "", password = "" });
            Assert.Equal(HttpStatusCode.Unauthorized, accepted.StatusCode);
        }
        using var denied = await second.PostAsJsonAsync("/api/auth/login", new { userName = "alice", password = Password });
        Assert.Equal(HttpStatusCode.TooManyRequests, denied.StatusCode);
        Assert.Equal("application/problem+json", denied.Content.Headers.ContentType?.MediaType);
        using var publicRoute = await second.GetAsync("/health");
        Assert.Equal(HttpStatusCode.OK, publicRoute.StatusCode);
        // Реальне хвилинне вікно робочої політики, без ослаблення ліміту в тесті.
        await Task.Delay(TimeSpan.FromSeconds(62));
        using var recovered = await second.PostAsJsonAsync("/api/auth/login", new { userName = "alice", password = Password });
        Assert.Equal(HttpStatusCode.NoContent, recovered.StatusCode);
    }
}
