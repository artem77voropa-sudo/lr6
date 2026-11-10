using SecureLab.Api.Scaffolding;
using SecureLab.Api.Security;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.EntityFrameworkCore;
using Scalar.AspNetCore;
using SecureLab.Api.Application.Incidents;
using SecureLab.Api.Data;
using SecureLab.Api.Presentation.Endpoints;

var builder = WebApplication.CreateBuilder(new WebApplicationOptions
{
    Args = args,
    WebRootPath = "Client"
});
builder.Services.AddOpenApi();
builder.Services.AddProblemDetails();
builder.Services.AddExceptionHandler<SafeExceptionHandler>();

var connectionString = builder.Configuration.GetConnectionString("SecureLab")
    ?? throw new InvalidOperationException(
        "Connection string 'SecureLab' не налаштовано.");

builder.Services.AddDbContext<SecureLabDbContext>(options =>
    options.UseNpgsql(connectionString));
builder.Services.AddHttpContextAccessor();
builder.Services.AddScoped<IncidentAccess>();
builder.Services.AddScoped<IncidentQueries>();

builder.AddLab03Identity();
builder.Services.AddAntiforgery(options =>
{
    options.HeaderName = CsrfProtection.Header;
    options.Cookie.Name = ".SecureLab.LR06.Antiforgery";
    options.Cookie.HttpOnly = true;
    options.Cookie.SameSite = SameSiteMode.Strict;
    options.Cookie.SecurePolicy = builder.Environment.IsDevelopment()
        ? CookieSecurePolicy.SameAsRequest : CookieSecurePolicy.Always;
});

// Temporary teaching origin; production uses the same-origin client.
if (builder.Environment.IsDevelopment())
{
    builder.Services.AddCors(options => options.AddPolicy("Lab05BrowserProbe", policy =>
        policy.WithOrigins("http://localhost:4173")
            .WithMethods("GET")
            .WithHeaders("X-Lab-Cors-Probe")
            .AllowCredentials()));
}

var app = builder.Build();

var resetRequested = args.Contains("--reset-database", StringComparer.Ordinal);
await DatabaseBootstrap.InitializeAsync(app.Services, app.Configuration, app.Environment, resetRequested);

if (resetRequested)
{
    return;
}

// Register before the exception handler; OnStarting reapplies headers after error response clearing.
app.Use(async (context, next) =>
{
    context.Response.OnStarting(() =>
    {
        context.Response.Headers.XContentTypeOptions = "nosniff";
        context.Response.Headers["Referrer-Policy"] = "no-referrer";
        if (!(app.Environment.IsDevelopment() && context.Request.Path.StartsWithSegments("/scalar")))
            context.Response.Headers["Content-Security-Policy"] =
                "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; " +
                "img-src 'self'; font-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'";
        return Task.CompletedTask;
    });
    await next(context);
});
app.UseExceptionHandler();
app.UseStatusCodePages();

if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
    app.MapScalarApiReference();
}

app.UseRouting();
if (app.Environment.IsDevelopment()) app.UseCors("Lab05BrowserProbe");
app.UseAuthentication();
app.UseAuthorization();
app.UseRateLimiter();

app.UseDefaultFiles();
app.UseStaticFiles();

app.MapGet("/health", async (SecureLabDbContext dbContext, CancellationToken cancellationToken) =>
    await dbContext.Database.CanConnectAsync(cancellationToken)
        ? Results.Ok(new { status = "ready" })
        : Results.Problem(
            title: "База даних недоступна",
            statusCode: StatusCodes.Status503ServiceUnavailable))
    .WithName("GetHealth")
    .Produces(StatusCodes.Status200OK)
    .ProducesProblem(StatusCodes.Status503ServiceUnavailable);

var csrfTokenEndpoint = app.MapGet(CsrfProtection.TokenRoute, (HttpContext context, IAntiforgery antiforgery) =>
    Results.Ok(new { token = antiforgery.GetAndStoreTokens(context).RequestToken }))
    .RequireAuthorization();
if (app.Environment.IsDevelopment())
    csrfTokenEndpoint.WithMetadata(new Microsoft.AspNetCore.Cors.DisableCorsAttribute());

app.MapIncidentEndpoints();
app.MapIncidentMutationEndpoints();
app.MapLab03Identity();
app.MapLab02Endpoints();
app.MapFallbackToFile("index.html");

app.Run();

public partial class Program;
