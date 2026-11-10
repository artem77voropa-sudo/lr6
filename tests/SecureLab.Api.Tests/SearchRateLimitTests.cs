using System.Net;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

namespace SecureLab.Api.Tests;

public sealed class SearchRateLimitTests
{
    [Fact]
    public async Task REG_RATE_SEARCH_AuthenticatedPartitions_QuotaRecoveryAndAuthorizationRemainSeparate()
    {
        using var factory = new SecureLabApiFactory();
        var password = Environment.GetEnvironmentVariable("SeedUsers__Password")!;
        using var alice = await factory.LoginAsync("alice", password);
        using var bob = await factory.LoginAsync("bob", password);
        for (var i=0;i<20;i++) Assert.Equal(HttpStatusCode.OK, (await alice.GetAsync("/api/incidents/search?q=USB")).StatusCode);
        Assert.Equal(HttpStatusCode.TooManyRequests, (await alice.GetAsync("/api/incidents/search?q=USB")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await bob.GetAsync("/api/incidents/search?q=USB")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await bob.GetAsync("/api/incidents/20000000-0000-0000-0000-000000000001")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await alice.GetAsync("/health")).StatusCode);
        await Task.Delay(TimeSpan.FromSeconds(11));
        Assert.Equal(HttpStatusCode.OK, (await alice.GetAsync("/api/incidents/search?q=USB")).StatusCode);
    }

    // This middleware exists only in the test host. No client header selects a production partition.
    private sealed class FixedIp(string ip) : IStartupFilter
    {
        public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next) => app =>
        {
            app.Use(async (context, continuation) => { context.Connection.RemoteIpAddress=IPAddress.Parse(ip); await continuation(context); });
            next(app);
        };
    }

    [Fact]
    public async Task REG_RATE_SEARCH_AnonymousClientsOnSameIpShareQuota()
    {
        using var factory=new SecureLabApiFactory();
        using var host=factory.WithWebHostBuilder(b=>b.ConfigureServices(s=>s.AddSingleton<IStartupFilter>(new FixedIp("127.0.0.42"))));
        using var first=host.CreateClient(); using var second=host.CreateClient();
        first.DefaultRequestHeaders.Add("X-Forwarded-For", "127.0.0.99");
        for(var i=0;i<20;i++) Assert.Equal(HttpStatusCode.OK,(await first.GetAsync("/api/incidents/search?q=USB")).StatusCode);
        Assert.Equal(HttpStatusCode.TooManyRequests,(await second.GetAsync("/api/incidents/search?q=USB")).StatusCode);
    }
}
