using System.Text.Json;
using KUserCenter.Common.Errors;

namespace KUserCenter.Middleware;

/// <summary>
/// 全局异常中间件：DomainException 按注册表映射的 HTTP 状态与稳定错误码输出错误信封；
/// 未预期异常统一映射 INTERNAL_ERROR（500），不暴露堆栈与内部细节。
/// </summary>
public sealed class ExceptionHandlingMiddleware
{
    private const string InternalErrorCode = "INTERNAL_ERROR";

    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    private readonly RequestDelegate _next;
    private readonly ILogger<ExceptionHandlingMiddleware> _logger;

    public ExceptionHandlingMiddleware(RequestDelegate next, ILogger<ExceptionHandlingMiddleware> logger)
    {
        _next = next;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        try
        {
            await _next(context);
        }
        catch (DomainException ex)
        {
            _logger.LogWarning("domain exception: code={Code}", ex.ErrorCode);
            await WriteEnvelopeAsync(context, ex.HttpStatus, new ErrorEnvelope(ex.ErrorCode, ex.Message));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "unhandled exception");
            await WriteEnvelopeAsync(context, StatusCodes.Status500InternalServerError,
                new ErrorEnvelope(InternalErrorCode, "Internal error"));
        }
    }

    private static async Task WriteEnvelopeAsync(HttpContext context, int status, ErrorEnvelope envelope)
    {
        if (context.Response.HasStarted)
        {
            return;
        }

        context.Response.Clear();
        context.Response.StatusCode = status;
        context.Response.ContentType = "application/problem+json";
        await context.Response.WriteAsync(JsonSerializer.Serialize(envelope, JsonOptions));
    }
}
