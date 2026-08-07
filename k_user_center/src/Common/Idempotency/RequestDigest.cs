using System.Security.Cryptography;
using System.Text;

namespace KUserCenter.Common.Idempotency;

/// <summary>
/// 规范化请求摘要：SHA-256 十六进制（char(64)），用于幂等键的同请求判定。
/// 调用方必须先完成请求规范化（字段排序、大小写、空白）再计算摘要；
/// 摘要不得包含敏感原文以外的推导信息，禁止把密码、验证码、Token 纳入摘要输入。
/// </summary>
public static class RequestDigest
{
    public static string ComputeSha256Hex(string canonicalRequest)
    {
        ArgumentException.ThrowIfNullOrEmpty(canonicalRequest);
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(canonicalRequest));
        return Convert.ToHexStringLower(bytes);
    }
}
