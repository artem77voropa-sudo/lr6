using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;

namespace SecureLab.Api.Tests;

public sealed class SecureLabApiFactory : WebApplicationFactory<Program>
{
    private HttpClient? _aliceClient;

    // РћРґРёРЅ СЂРµР°Р»СЊРЅРёР№ СЃРµР°РЅСЃ РЅР° fixture: СЂРµРіСЂРµСЃС–С— Р›Р 2 РЅРµ РІРёС‚СЂР°С‡Р°СЋС‚СЊ login quota РЅР° РєРѕР¶РЅРёР№ POST.
    public async Task<HttpClient> AliceClientAsync()
    {
        if (_aliceClient is not null) return _aliceClient;
        _aliceClient = await this.LoginAsync("alice", Environment.GetEnvironmentVariable("SeedUsers__Password")
            ?? throw new InvalidOperationException("Set local SeedUsers__Password outside Git."));
        await _aliceClient.UseAntiforgeryTokenAsync();
        return _aliceClient;
    }

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Development");
    }
}
