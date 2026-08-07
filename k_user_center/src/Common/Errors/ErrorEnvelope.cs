namespace KUserCenter.Common.Errors;

/// <summary>
/// 稳定错误信封：对外只暴露已登记的错误码与稳定语义；
/// 通用 500 不暴露内部细节（错误码须先在 docs/代码实施/错误码注册表.csv 登记）。
/// </summary>
public sealed record ErrorEnvelope(string Code, string Message, string? TraceId = null);
