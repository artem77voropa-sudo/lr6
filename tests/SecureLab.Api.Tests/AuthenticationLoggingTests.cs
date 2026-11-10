using System.Collections.Concurrent;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace SecureLab.Api.Tests;

public sealed class AuthenticationLoggingTests(SecureLabApiFactory factory) : IClassFixture<SecureLabApiFactory>
{
    private sealed class EventSink : ILoggerProvider
    {
        public ConcurrentQueue<string[]> Fields { get; } = new();
        public ConcurrentQueue<string> Messages { get; } = new();
        public ILogger CreateLogger(string categoryName) => new SinkLogger(this, categoryName);
        public void Dispose() { }
        private sealed class SinkLogger(EventSink sink, string category) : ILogger
        {
            public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
            public bool IsEnabled(LogLevel level) => category == "SecureLab.Authentication";
            public void Log<TState>(LogLevel level, EventId eventId, TState state, Exception? exception,
                Func<TState, Exception?, string> formatter)
            {
                if (!IsEnabled(level)) return;
                sink.Messages.Enqueue(formatter(state, exception));
                if (state is IEnumerable<KeyValuePair<string, object?>> properties)
                    sink.Fields.Enqueue(properties.Select(p => p.Key).ToArray());
            }
        }
    }

    [Fact]
    public async Task S01_AuthenticationEvents_ContainOnlyApprovedFields()
    {
        var sink = new EventSink();
        using var host = factory.WithWebHostBuilder(builder => builder.ConfigureServices(services =>
            services.AddSingleton<ILoggerProvider>(sink)));
        using var client = host.CreateClient(new() { BaseAddress = new Uri("https://localhost") });
        var password = Environment.GetEnvironmentVariable("SeedUsers__Password")
            ?? throw new InvalidOperationException("Set local SeedUsers__Password outside Git.");
        using var login = await client.PostAsJsonAsync("/api/auth/login", new { userName = "alice", password });
        Assert.Equal(System.Net.HttpStatusCode.NoContent, login.StatusCode);
        await client.UseAntiforgeryTokenAsync();
        using var logout = await client.PostAsync("/api/auth/logout", null);
        using var invalid = await client.PostAsJsonAsync("/api/auth/login", new { userName = "absent", password });
        Assert.True(sink.Messages.Count >= 3);
        foreach (var fields in sink.Fields)
            Assert.Equal(new[] { "EventType", "Result", "TraceId", "UtcTime", "{OriginalFormat}" }, fields.Order(StringComparer.Ordinal).ToArray());
        foreach (var message in sink.Messages)
        {
            Assert.False(message.Contains(password, StringComparison.Ordinal));
            Assert.False(message.Contains(".AspNetCore.Identity.Application", StringComparison.Ordinal));
            Assert.False(message.Contains("PasswordHash", StringComparison.OrdinalIgnoreCase));
        }
    }
}
