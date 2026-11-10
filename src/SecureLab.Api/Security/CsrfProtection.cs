using Microsoft.AspNetCore.Antiforgery;

namespace SecureLab.Api.Security;

public sealed class CsrfProtection(IAntiforgery antiforgery) : IEndpointFilter
{
    public const string Header = "X-CSRF-TOKEN";
    public const string TokenRoute = "/api/auth/csrf-token";

    public async ValueTask<object?> InvokeAsync(EndpointFilterInvocationContext invocation, EndpointFilterDelegate next)
    {
        try
        {
            await antiforgery.ValidateRequestAsync(invocation.HttpContext);
        }
        catch (AntiforgeryValidationException)
        {
            // Never log the exception text, request token, cookie or request body.
            return Results.Problem(statusCode: StatusCodes.Status400BadRequest,
                title: "Запит не пройшов перевірку CSRF",
                extensions: new Dictionary<string, object?> { ["code"] = "csrf_validation_failed" });
        }
        return await next(invocation);
    }
}
