using KUserCenter.Common.Errors;
using KUserCenter.Common.Ids;
using KUserCenter.Common.Outbox;
using SqlSugar;

namespace KUserCenter.Repositories;

/// <summary>
/// iam.outbox_events 适配器（阶段 0 技术探针）：核心信封字段全部显式列写入，
/// 不隐藏于 headers；在调用方当前事务内追加，发布状态机由 EVENT 代码维护。
/// </summary>
public sealed class SqlSugarOutboxWriter : IOutboxWriter
{
    private const string PendingPublishState = "PENDING";

    private readonly ISqlSugarClient _client;
    private readonly PersistenceErrorTranslator _translator;

    public SqlSugarOutboxWriter(ISqlSugarClient client, PersistenceErrorTranslator translator)
    {
        _client = client;
        _translator = translator;
    }

    public async Task AppendAsync(OutboxMessage message, CancellationToken cancellationToken = default)
    {
        try
        {
            await _client.Ado.ExecuteCommandAsync(
                """
                INSERT INTO iam.outbox_events
                    (id, event_id, event_type, schema_version,
                     aggregate_type, aggregate_id, aggregate_version,
                     tenant_id, business_line_id,
                     producer_type, producer_id,
                     subject_ref_type, subject_ref_id,
                     actor_type, actor_id_type, actor_id,
                     occurred_at, data_version,
                     trace_id, correlation_id, causation_id,
                     data_classification, payload, headers, publish_state)
                VALUES
                    (@id, @eventId, @eventType, @schemaVersion,
                     @aggregateType, @aggregateId, @aggregateVersion,
                     @tenantId, @businessLineId,
                     @producerType, @producerId,
                     @subjectRefType, @subjectRefId,
                     @actorType, @actorIdType, @actorId,
                     @occurredAt, @dataVersion,
                     @traceId, @correlationId, @causationId,
                     @dataClassification, @payload::jsonb, @headers::jsonb, @publishState)
                """,
                // SqlSugar Ado 不支持 CancellationToken，取消语义由外层事务作用域保障。
                new SugarParameter("@id", Uuid7.New()),
                new SugarParameter("@eventId", message.EventId),
                new SugarParameter("@eventType", message.EventType),
                new SugarParameter("@schemaVersion", message.SchemaVersion),
                new SugarParameter("@aggregateType", message.AggregateType),
                new SugarParameter("@aggregateId", message.AggregateId),
                new SugarParameter("@aggregateVersion", (object?)message.AggregateVersion),
                new SugarParameter("@tenantId", (object?)message.TenantId),
                new SugarParameter("@businessLineId", (object?)message.BusinessLineId),
                new SugarParameter("@producerType", message.ProducerType),
                new SugarParameter("@producerId", message.ProducerId),
                new SugarParameter("@subjectRefType", message.SubjectRefType),
                new SugarParameter("@subjectRefId", message.SubjectRefId),
                new SugarParameter("@actorType", (object?)message.ActorType),
                new SugarParameter("@actorIdType", (object?)message.ActorIdType),
                new SugarParameter("@actorId", (object?)message.ActorId),
                new SugarParameter("@occurredAt", message.OccurredAt.UtcDateTime),
                new SugarParameter("@dataVersion", (object?)message.DataVersion),
                new SugarParameter("@traceId", message.TraceId),
                new SugarParameter("@correlationId", (object?)message.CorrelationId),
                new SugarParameter("@causationId", (object?)message.CausationId),
                new SugarParameter("@dataClassification", message.DataClassification),
                new SugarParameter("@payload", message.PayloadJson),
                new SugarParameter("@headers", message.HeadersJson),
                new SugarParameter("@publishState", PendingPublishState)).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            throw _translator.Translate(NpgsqlFaultClassifier.Classify(ex));
        }
    }
}
