using System.Diagnostics;
using Microsoft.AspNetCore.Diagnostics;

namespace SecureLab.Api.Security;

public sealed class SafeExceptionHandler(ILogger<SafeExceptionHandler> logger) : IExceptionHandler
{
    public async ValueTask<bool> TryHandleAsync(HttpContext context, Exception exception, CancellationToken cancellationToken)
    {
        var trace = Activity.Current?.Id ?? context.TraceIdentifier;
        logger.LogError("UnexpectedFailure trace={TraceId} exceptionType={ExceptionType} utc={UtcTime}",
            trace, exception.GetType().Name, DateTimeOffset.UtcNow);
        await Results.Problem(statusCode: 500, title: "Операцію не завершено",
            extensions: new Dictionary<string, object?> { ["traceId"] = trace }).ExecuteAsync(context);
        return true;
    }
}
