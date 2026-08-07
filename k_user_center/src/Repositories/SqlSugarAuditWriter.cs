using KUserCenter.Common.Audit;
using KUserCenter.Common.Errors;
using KUserCenter.Common.Ids;
using SqlSugar;

namespace KUserCenter.Repositories;

/// <summary>
/// iam.audit_events 适配器（阶段 0 技术探针）：不可变追加；
/// 在调用方当前事务内写入并返回审计事件 ID，供审计投递 Outbox 引用。
/// 审计失败向上抛出导致整体回滚（失败关闭）；普通角色不得 UPDATE/DELETE。
/// </summary>
public sealed class SqlSugarAuditWriter : IAuditWriter
{
    private readonly ISqlSugarClient _client;
    private readonly PersistenceErrorTranslator _translator;

    public SqlSugarAuditWriter(ISqlSugarClient client, PersistenceErrorTranslator translator)
    {
        _client = client;
        _translator = translator;
    }

    public async Task<Guid> AppendAsync(AuditEntry entry, CancellationToken cancellationToken = default)
    {
        var eventId = Uuid7.New();
        try
        {
            await _client.Ado.ExecuteCommandAsync(
                """
                INSERT INTO iam.audit_events
                    (id, event_id, actor_type, actor_id,
                     subject_type, subject_id, tenant_id,
                     action, object_type, object_id, outcome, reason_code,
                     before_digest, after_digest, approval_case_id,
                     trace_id, attributes, occurred_at)
                VALUES
                    (@id, @eventId, @actorType, @actorId,
                     @subjectType, @subjectId, @tenantId,
                     @action, @objectType, @objectId, @outcome, @reasonCode,
                     @beforeDigest, @afterDigest, @approvalCaseId,
                     @traceId, @attributes::jsonb, @occurredAt)
                """,
                // SqlSugar Ado 不支持 CancellationToken，取消语义由外层事务作用域保障。
                new SugarParameter("@id", Uuid7.New()),
                new SugarParameter("@eventId", eventId),
                new SugarParameter("@actorType", (object?)entry.ActorType),
                new SugarParameter("@actorId", (object?)entry.ActorId),
                new SugarParameter("@subjectType", (object?)entry.SubjectType),
                new SugarParameter("@subjectId", (object?)entry.SubjectId),
                new SugarParameter("@tenantId", (object?)entry.TenantId),
                new SugarParameter("@action", entry.Action),
                new SugarParameter("@objectType", entry.ObjectType),
                new SugarParameter("@objectId", (object?)entry.ObjectId),
                new SugarParameter("@outcome", entry.Outcome),
                new SugarParameter("@reasonCode", (object?)entry.ReasonCode),
                new SugarParameter("@beforeDigest", (object?)entry.BeforeDigest),
                new SugarParameter("@afterDigest", (object?)entry.AfterDigest),
                new SugarParameter("@approvalCaseId", (object?)entry.ApprovalCaseId),
                new SugarParameter("@traceId", (object?)entry.TraceId),
                new SugarParameter("@attributes", entry.AttributesJson ?? "{}"),
                new SugarParameter("@occurredAt", entry.OccurredAt.UtcDateTime)).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            throw _translator.Translate(NpgsqlFaultClassifier.Classify(ex));
        }

        return eventId;
    }
}
