using System.Net.Http.Json;
using SecureLab.Api.Security;

namespace SecureLab.Api.Tests;

public static class AntiforgeryTestExtensions
{
    private sealed record TokenResponse(string Token);

    // Explicit opt-in for ordinary mutation tests; CSRF-negative tests do not call this.
    public static async Task UseAntiforgeryTokenAsync(this HttpClient client)
    {
        client.DefaultRequestHeaders.Remove(CsrfProtection.Header);
        using var response = await client.GetAsync(CsrfProtection.TokenRoute);
        response.EnsureSuccessStatusCode();
        var body = await response.Content.ReadFromJsonAsync<TokenResponse>();
        if (string.IsNullOrWhiteSpace(body?.Token)) throw new InvalidOperationException("Request token missing.");
        client.DefaultRequestHeaders.Add(CsrfProtection.Header, body.Token);
    }
}
