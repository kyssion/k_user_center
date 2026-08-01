-- =============================================================================
-- 060_integration_audit_messaging.sql
-- 事件/Outbox/Webhook、不可篡改审计、消息投递与可达性
-- =============================================================================

BEGIN;
SET LOCAL lock_timeout = '10s';
SET LOCAL statement_timeout = '5min';

CREATE TABLE integration.event_schema (
    event_type            text        NOT NULL,
    schema_version        integer     NOT NULL,
    compatibility_mode    text        NOT NULL DEFAULT 'BACKWARD',
    json_schema           jsonb       NOT NULL,
    schema_hash           bytea       NOT NULL,
    maximum_classification text       NOT NULL,
    owner_ref             text        NOT NULL,
    release_id            uuid        NULL,
    is_active             boolean     NOT NULL DEFAULT false,
    created_at            timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT pk_event_schema PRIMARY KEY (event_type, schema_version),
    CONSTRAINT fk_event_schema_class FOREIGN KEY (maximum_classification) REFERENCES core.data_classification(classification_code),
    CONSTRAINT fk_event_schema_release FOREIGN KEY (release_id) REFERENCES control.config_release(id),
    CONSTRAINT ck_event_schema_type CHECK (event_type ~ '^[a-z][a-z0-9_.-]{2,127}$'),
    CONSTRAINT ck_event_schema_compat CHECK (compatibility_mode IN ('BACKWARD', 'FORWARD', 'FULL', 'NONE')),
    CONSTRAINT ck_event_schema_hash CHECK (octet_length(schema_hash) = 32),
    CONSTRAINT ck_event_schema_active CHECK (NOT is_active OR release_id IS NOT NULL)
);
COMMENT ON TABLE integration.event_schema IS 'EVT-G-001/005：事件类型、Schema 版本、兼容模式、分类上限和受控发布记录。';

CREATE TABLE integration.outbox_event (
    id                    uuid        NOT NULL DEFAULT gen_random_uuid(),
    event_id              uuid        NOT NULL DEFAULT gen_random_uuid(),
    event_type            text        NOT NULL,
    schema_version        integer     NOT NULL,
    aggregate_kind        text        NOT NULL,
    aggregate_ref         text        NOT NULL,
    aggregate_version     bigint      NOT NULL,
    subject_ref_type      text        NULL,
    subject_ref           text        NULL,
    actor_ref_type        text        NULL,
    actor_ref             text        NULL,
    tenant_id             uuid        NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
    business_line_id      uuid        NULL,
    payload               jsonb       NOT NULL,
    payload_hash          bytea       NOT NULL,
    trace_id              text        NULL,
    correlation_id        text        NOT NULL,
    causation_id          uuid        NULL,
    occurred_at           timestamptz NOT NULL,
    available_at          timestamptz NOT NULL DEFAULT clock_timestamp(),
    publish_state         text        NOT NULL DEFAULT 'PENDING',
    attempt_count         integer     NOT NULL DEFAULT 0,
    next_attempt_at       timestamptz NULL,
    published_at          timestamptz NULL,
    broker_partition      text        NULL,
    broker_offset         text        NULL,
    last_error_code       text        NULL,
    created_at            timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT pk_outbox_event PRIMARY KEY (id),
    CONSTRAINT uq_outbox_event_id UNIQUE (event_id),
    CONSTRAINT fk_outbox_event_schema FOREIGN KEY (event_type, schema_version) REFERENCES integration.event_schema(event_type, schema_version),
    CONSTRAINT ck_outbox_event_subject CHECK ((subject_ref_type IS NULL) = (subject_ref IS NULL)),
    CONSTRAINT ck_outbox_event_actor CHECK ((actor_ref_type IS NULL) = (actor_ref IS NULL)),
    CONSTRAINT ck_outbox_event_subject_type CHECK (subject_ref_type IS NULL OR subject_ref_type IN ('GLOBAL_USER', 'PAIRWISE_SUBJECT', 'MEMBERSHIP', 'CLIENT', 'MACHINE', 'TOMBSTONE')),
    CONSTRAINT ck_outbox_event_actor_type CHECK (actor_ref_type IS NULL OR actor_ref_type IN ('GLOBAL_USER', 'PAIRWISE_SUBJECT', 'MEMBERSHIP', 'CLIENT', 'MACHINE', 'SYSTEM')),
    CONSTRAINT ck_outbox_event_version CHECK (aggregate_version >= 1),
    CONSTRAINT ck_outbox_event_hash CHECK (octet_length(payload_hash) = 32),
    CONSTRAINT ck_outbox_event_state CHECK (publish_state IN ('PENDING', 'PUBLISHING', 'PUBLISHED', 'FAILED', 'DEAD_LETTER')),
    CONSTRAINT ck_outbox_event_attempt CHECK (attempt_count >= 0),
    CONSTRAINT ck_outbox_event_published CHECK ((publish_state = 'PUBLISHED') = (published_at IS NOT NULL))
);
COMMENT ON TABLE integration.outbox_event IS 'INV-G-010 / EVT-G-001 至 004：与领域状态同事务提交的标准事件信封、版本、顺序、幂等与发布水位。';

CREATE TABLE integration.webhook_subscription (
    id                    uuid        NOT NULL DEFAULT gen_random_uuid(),
    public_id             text        NOT NULL,
    client_id             uuid        NOT NULL,
    tenant_id             uuid        NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
    subscription_state    text        NOT NULL DEFAULT 'PENDING_VERIFICATION',
    callback_uri          text        NOT NULL,
    resolved_address_hash bytea       NOT NULL,
    tls_certificate_pin   bytea       NULL,
    signing_key_ref       text        NOT NULL,
    event_types           text[]      NOT NULL,
    maximum_classification text       NOT NULL,
    consent_purpose_code  text        NULL,
    consent_aggregate_id  uuid        NULL,
    consent_epoch         bigint      NULL,
    verification_challenge_hash bytea NOT NULL,
    verified_at           timestamptz NULL,
    expires_at            timestamptz NOT NULL,
    created_at            timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at            timestamptz NOT NULL DEFAULT clock_timestamp(),
    row_version           bigint      NOT NULL DEFAULT 1,
    CONSTRAINT pk_webhook_subscription PRIMARY KEY (id),
    CONSTRAINT uq_webhook_subscription_public_id UNIQUE (public_id),
    CONSTRAINT uq_webhook_subscription_uri UNIQUE (client_id, callback_uri),
    CONSTRAINT fk_webhook_subscription_client FOREIGN KEY (client_id) REFERENCES oauth.client(id),
    CONSTRAINT fk_webhook_subscription_class FOREIGN KEY (maximum_classification) REFERENCES core.data_classification(classification_code),
    CONSTRAINT fk_webhook_subscription_consent FOREIGN KEY (consent_aggregate_id) REFERENCES privacy.consent_aggregate(id),
    CONSTRAINT ck_webhook_subscription_state CHECK (subscription_state IN ('PENDING_VERIFICATION', 'ACTIVE', 'SUSPENDED', 'REVOKED', 'EXPIRED')),
    CONSTRAINT ck_webhook_subscription_uri CHECK (callback_uri ~ '^https://'),
    CONSTRAINT ck_webhook_subscription_events CHECK (cardinality(event_types) > 0),
    CONSTRAINT ck_webhook_subscription_hash CHECK (octet_length(resolved_address_hash) = 32 AND octet_length(verification_challenge_hash) = 32),
    CONSTRAINT ck_webhook_subscription_consent CHECK (
        (consent_aggregate_id IS NULL AND consent_epoch IS NULL AND consent_purpose_code IS NULL)
        OR (consent_aggregate_id IS NOT NULL AND consent_epoch IS NOT NULL AND consent_purpose_code IS NOT NULL)
    ),
    CONSTRAINT ck_webhook_subscription_active CHECK (subscription_state <> 'ACTIVE' OR verified_at IS NOT NULL),
    CONSTRAINT ck_webhook_subscription_expiry CHECK (expires_at > created_at)
);
COMMENT ON TABLE integration.webhook_subscription IS 'CAP-EVENT-003/004：HTTPS、SSRF 校验、签名密钥、事件范围、分类上限和可选 Consent 水位的 Webhook 订阅。';

CREATE TABLE integration.webhook_delivery (
    id                    uuid        NOT NULL DEFAULT gen_random_uuid(),
    public_id             text        NOT NULL,
    subscription_id       uuid        NOT NULL,
    event_id              uuid        NOT NULL,
    delivery_state        text        NOT NULL DEFAULT 'PENDING',
    delivery_attempt      integer     NOT NULL DEFAULT 0,
    contains_personal_subject boolean NOT NULL DEFAULT false,
    recipient_subject_ref_type text   NULL,
    recipient_subject_ref text        NULL,
    recipient_actor_ref_type text     NULL,
    recipient_actor_ref   text        NULL,
    payload_hash          bytea       NOT NULL,
    signature_key_ref     text        NOT NULL,
    signature_hash        bytea       NOT NULL,
    response_status       integer     NULL,
    response_body_hash    bytea       NULL,
    next_attempt_at       timestamptz NULL,
    first_attempt_at      timestamptz NULL,
    delivered_at          timestamptz NULL,
    dead_lettered_at      timestamptz NULL,
    created_at            timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT pk_webhook_delivery PRIMARY KEY (id),
    CONSTRAINT uq_webhook_delivery_public_id UNIQUE (public_id),
    CONSTRAINT uq_webhook_delivery_attempt UNIQUE (subscription_id, event_id, delivery_attempt),
    CONSTRAINT fk_webhook_delivery_subscription FOREIGN KEY (subscription_id) REFERENCES integration.webhook_subscription(id),
    CONSTRAINT fk_webhook_delivery_event FOREIGN KEY (event_id) REFERENCES integration.outbox_event(event_id),
    CONSTRAINT ck_webhook_delivery_state CHECK (delivery_state IN ('PENDING', 'SENDING', 'DELIVERED', 'FAILED', 'DEAD_LETTER', 'CANCELLED')),
    CONSTRAINT ck_webhook_delivery_attempt CHECK (delivery_attempt >= 0),
    CONSTRAINT ck_webhook_delivery_subject CHECK (
        (NOT contains_personal_subject AND recipient_subject_ref_type IS NULL AND recipient_subject_ref IS NULL)
        OR (contains_personal_subject AND recipient_subject_ref_type = 'PAIRWISE_SUBJECT' AND recipient_subject_ref IS NOT NULL)
    ),
    CONSTRAINT ck_webhook_delivery_actor CHECK ((recipient_actor_ref_type IS NULL) = (recipient_actor_ref IS NULL)),
    CONSTRAINT ck_webhook_delivery_no_global_actor CHECK (recipient_actor_ref_type IS NULL OR recipient_actor_ref_type IN ('PAIRWISE_SUBJECT', 'CLIENT', 'MACHINE', 'SYSTEM')),
    CONSTRAINT ck_webhook_delivery_hash CHECK (octet_length(payload_hash) = 32 AND octet_length(signature_hash) = 32),
    CONSTRAINT ck_webhook_delivery_delivered CHECK ((delivery_state = 'DELIVERED') = (delivered_at IS NOT NULL)),
    CONSTRAINT ck_webhook_delivery_dead CHECK ((delivery_state = 'DEAD_LETTER') = (dead_lettered_at IS NOT NULL))
);
COMMENT ON TABLE integration.webhook_delivery IS 'CAP-EVENT-005/012/015：签名、防重放、逐次重试/死信证据；个人事件对每个 Client 仅使用 pairwise Subject。';

CREATE TABLE integration.consumer_watermark (
    consumer_code         text        NOT NULL,
    tenant_id             uuid        NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
    event_type            text        NOT NULL,
    last_event_id         uuid        NULL,
    last_aggregate_version bigint     NOT NULL DEFAULT 0,
    security_epochs       jsonb       NOT NULL DEFAULT '{}',
    consent_epochs        jsonb       NOT NULL DEFAULT '{}',
    updated_at            timestamptz NOT NULL DEFAULT clock_timestamp(),
    row_version           bigint      NOT NULL DEFAULT 1,
    CONSTRAINT pk_consumer_watermark PRIMARY KEY (consumer_code, tenant_id, event_type),
    CONSTRAINT ck_consumer_watermark_version CHECK (last_aggregate_version >= 0)
);
COMMENT ON TABLE integration.consumer_watermark IS 'CAP-EVENT-007/009：消费方事件版本、security epoch 和 consent epoch 水位及断档补拉起点。';

CREATE TABLE integration.event_replay_request (
    id                    uuid        NOT NULL DEFAULT gen_random_uuid(),
    public_id             text        NOT NULL,
    operation_id          uuid        NOT NULL,
    approval_case_id      uuid        NOT NULL,
    requested_by_ref      text        NOT NULL,
    event_type_patterns   text[]      NOT NULL,
    tenant_ids            uuid[]      NOT NULL DEFAULT '{}',
    occurred_from         timestamptz NOT NULL,
    occurred_until        timestamptz NOT NULL,
    replay_state          text        NOT NULL DEFAULT 'PENDING',
    suppress_irreversible_side_effects boolean NOT NULL DEFAULT true,
    replayed_count        bigint      NOT NULL DEFAULT 0,
    failed_count          bigint      NOT NULL DEFAULT 0,
    created_at            timestamptz NOT NULL DEFAULT clock_timestamp(),
    completed_at          timestamptz NULL,
    CONSTRAINT pk_event_replay_request PRIMARY KEY (id),
    CONSTRAINT uq_event_replay_request_public_id UNIQUE (public_id),
    CONSTRAINT uq_event_replay_request_operation UNIQUE (operation_id),
    CONSTRAINT fk_event_replay_operation FOREIGN KEY (operation_id) REFERENCES core.async_operation(id),
    CONSTRAINT fk_event_replay_approval FOREIGN KEY (approval_case_id) REFERENCES control.approval_case(id),
    CONSTRAINT ck_event_replay_state CHECK (replay_state IN ('PENDING', 'RUNNING', 'PARTIAL', 'COMPLETED', 'FAILED', 'CANCELLED')),
    CONSTRAINT ck_event_replay_window CHECK (occurred_until > occurred_from),
    CONSTRAINT ck_event_replay_count CHECK (replayed_count >= 0 AND failed_count >= 0)
);
COMMENT ON TABLE integration.event_replay_request IS 'EVT-G-008：审批、时间/租户/类型范围、审计和不可逆副作用抑制明确的事件回放 Operation。';

CREATE TABLE audit.audit_outbox (
    id                    uuid        NOT NULL DEFAULT gen_random_uuid(),
    audit_event_id        uuid        NOT NULL,
    audit_type            text        NOT NULL,
    event_payload_ciphertext bytea    NOT NULL,
    payload_hash          bytea       NOT NULL,
    encryption_key_ref    text        NOT NULL,
    persistence_state     text        NOT NULL DEFAULT 'PERSISTED',
    remote_persisted_at   timestamptz NULL,
    created_at            timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT pk_audit_outbox PRIMARY KEY (id),
    CONSTRAINT uq_audit_outbox_event UNIQUE (audit_event_id),
    CONSTRAINT ck_audit_outbox_hash CHECK (octet_length(payload_hash) = 32),
    CONSTRAINT ck_audit_outbox_state CHECK (persistence_state IN ('PERSISTED', 'DELIVERING', 'REMOTE_PERSISTED', 'FAILED')),
    CONSTRAINT ck_audit_outbox_remote CHECK ((persistence_state = 'REMOTE_PERSISTED') = (remote_persisted_at IS NOT NULL))
);
COMMENT ON TABLE audit.audit_outbox IS 'INV-G-008：高风险业务事务本地原子写入的加密审计证据；落盘失败时业务写入失败关闭。';

CREATE TABLE audit.audit_event (
    id                    uuid        NOT NULL DEFAULT gen_random_uuid(),
    audit_event_id        uuid        NOT NULL,
    audit_type            text        NOT NULL,
    actor_kind            text        NOT NULL,
    actor_ref             text        NOT NULL,
    subject_kind          text        NULL,
    subject_ref           text        NULL,
    tenant_id             uuid        NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
    source_kind           text        NOT NULL,
    source_ref_hash       bytea       NULL,
    action_code           text        NOT NULL,
    object_kind           text        NOT NULL,
    object_ref            text        NOT NULL,
    before_version        text        NULL,
    after_version         text        NULL,
    before_value_hash     bytea       NULL,
    after_value_hash      bytea       NULL,
    reason_code           text        NULL,
    approval_case_id      uuid        NULL,
    decision_id           uuid        NULL,
    result_code           text        NOT NULL,
    policy_version        bigint      NULL,
    trace_id              text        NOT NULL,
    correlation_id        text        NULL,
    classification_code   text        NOT NULL,
    retention_rule_code   text        NOT NULL,
    legal_basis           text        NOT NULL,
    previous_event_hash   bytea       NULL,
    event_hash            bytea       NOT NULL,
    chain_partition       text        NOT NULL,
    chain_sequence        bigint      NOT NULL,
    occurred_at           timestamptz NOT NULL,
    ingested_at           timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT pk_audit_event PRIMARY KEY (id),
    CONSTRAINT uq_audit_event_id UNIQUE (audit_event_id),
    CONSTRAINT uq_audit_event_chain UNIQUE (chain_partition, chain_sequence),
    CONSTRAINT fk_audit_event_approval FOREIGN KEY (approval_case_id) REFERENCES control.approval_case(id),
    CONSTRAINT fk_audit_event_decision FOREIGN KEY (decision_id) REFERENCES authz.authorization_decision(id),
    CONSTRAINT fk_audit_event_class FOREIGN KEY (classification_code) REFERENCES core.data_classification(classification_code),
    CONSTRAINT ck_audit_event_subject CHECK ((subject_kind IS NULL) = (subject_ref IS NULL)),
    CONSTRAINT ck_audit_event_actor CHECK (actor_kind IN ('USER', 'ADMIN', 'CLIENT', 'MACHINE', 'SYSTEM', 'IDENTITY_PROVIDER')),
    CONSTRAINT ck_audit_event_result CHECK (result_code IN ('SUCCEEDED', 'DENIED', 'FAILED', 'PARTIAL', 'CANCELLED')),
    CONSTRAINT ck_audit_event_hash CHECK (octet_length(event_hash) = 32 AND (previous_event_hash IS NULL OR octet_length(previous_event_hash) = 32)),
    CONSTRAINT ck_audit_event_sequence CHECK (chain_sequence >= 1)
);
COMMENT ON TABLE audit.audit_event IS 'REQ-CTRL 审计契约：操作者、Actor、Subject、范围、前后版本/摘要、原因、审批、结果、trace、策略和哈希链。';

CREATE TABLE audit.audit_seal (
    id                    uuid        NOT NULL DEFAULT gen_random_uuid(),
    chain_partition       text        NOT NULL,
    sequence_from         bigint      NOT NULL,
    sequence_until        bigint      NOT NULL,
    root_hash             bytea       NOT NULL,
    signing_key_ref       text        NOT NULL,
    signature             bytea       NOT NULL,
    external_timestamp_ref text       NULL,
    sealed_at             timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT pk_audit_seal PRIMARY KEY (id),
    CONSTRAINT uq_audit_seal_range UNIQUE (chain_partition, sequence_from, sequence_until),
    CONSTRAINT ck_audit_seal_range CHECK (sequence_from >= 1 AND sequence_until >= sequence_from),
    CONSTRAINT ck_audit_seal_hash CHECK (octet_length(root_hash) = 32)
);
COMMENT ON TABLE audit.audit_seal IS '审计哈希链批次的根摘要、签名密钥与可选外部可信时间戳封存证明。';

CREATE TABLE audit.data_access_event (
    id                    uuid        NOT NULL DEFAULT gen_random_uuid(),
    actor_kind            text        NOT NULL,
    actor_ref             text        NOT NULL,
    tenant_id             uuid        NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
    purpose_code          text        NOT NULL,
    category_codes        text[]      NOT NULL,
    operation_kind        text        NOT NULL,
    query_shape_hash      bytea       NOT NULL,
    row_count             bigint      NOT NULL,
    decision_id           uuid        NOT NULL,
    result_code           text        NOT NULL,
    trace_id              text        NOT NULL,
    accessed_at           timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT pk_data_access_event PRIMARY KEY (id),
    CONSTRAINT fk_data_access_decision FOREIGN KEY (decision_id) REFERENCES authz.authorization_decision(id),
    CONSTRAINT ck_data_access_categories CHECK (cardinality(category_codes) > 0),
    CONSTRAINT ck_data_access_operation CHECK (operation_kind IN ('READ', 'SEARCH', 'EXPORT', 'BULK_READ', 'BLIND_INDEX_LOOKUP', 'AUDIT_QUERY')),
    CONSTRAINT ck_data_access_hash CHECK (octet_length(query_shape_hash) = 32),
    CONSTRAINT ck_data_access_count CHECK (row_count >= 0),
    CONSTRAINT ck_data_access_result CHECK (result_code IN ('SUCCEEDED', 'DENIED', 'FAILED'))
);
COMMENT ON TABLE audit.data_access_event IS 'REQ-KEY-009 / 隐私审计：敏感读取、搜索、导出、盲索引与审计查询本身的用途、类别、决策和查询形状。';

CREATE TABLE messaging.provider (
    id                    uuid        NOT NULL DEFAULT gen_random_uuid(),
    provider_code         text        NOT NULL,
    channel_code          text        NOT NULL,
    provider_state        text        NOT NULL DEFAULT 'DRAFT',
    endpoint_uri          text        NOT NULL,
    credential_key_ref    text        NOT NULL,
    region_code           text        NOT NULL,
    supports_idempotency  boolean     NOT NULL DEFAULT false,
    rate_limit_per_second integer     NOT NULL,
    owner_ref             text        NOT NULL,
    created_at            timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at            timestamptz NOT NULL DEFAULT clock_timestamp(),
    row_version           bigint      NOT NULL DEFAULT 1,
    CONSTRAINT pk_messaging_provider PRIMARY KEY (id),
    CONSTRAINT uq_messaging_provider_code UNIQUE (provider_code),
    CONSTRAINT ck_messaging_provider_channel CHECK (channel_code IN ('SMS', 'EMAIL', 'VOICE', 'PUSH', 'IN_APP')),
    CONSTRAINT ck_messaging_provider_state CHECK (provider_state IN ('DRAFT', 'ACTIVE', 'DEGRADED', 'SUSPENDED', 'RETIRED')),
    CONSTRAINT ck_messaging_provider_rate CHECK (rate_limit_per_second > 0)
);
COMMENT ON TABLE messaging.provider IS 'CAP-MSG-001/003：消息供应商、通道、凭证引用、区域、幂等和限流能力。';

CREATE TABLE messaging.route_policy (
    id                    uuid        NOT NULL DEFAULT gen_random_uuid(),
    route_code            text        NOT NULL,
    route_version         integer     NOT NULL,
    channel_code          text        NOT NULL,
    purpose_code          text        NOT NULL,
    region_code           text        NOT NULL,
    provider_ids          uuid[]      NOT NULL,
    fallback_channels     text[]      NOT NULL DEFAULT '{}',
    max_attempts          integer     NOT NULL,
    fail_closed           boolean     NOT NULL DEFAULT true,
    is_active             boolean     NOT NULL DEFAULT false,
    effective_at          timestamptz NOT NULL,
    CONSTRAINT pk_route_policy PRIMARY KEY (id),
    CONSTRAINT uq_route_policy_version UNIQUE (route_code, route_version),
    CONSTRAINT ck_route_policy_channel CHECK (channel_code IN ('SMS', 'EMAIL', 'VOICE', 'PUSH', 'IN_APP')),
    CONSTRAINT ck_route_policy_providers CHECK (cardinality(provider_ids) > 0),
    CONSTRAINT ck_route_policy_attempt CHECK (max_attempts BETWEEN 1 AND 10)
);
COMMENT ON TABLE messaging.route_policy IS 'CAP-MSG-003：按用途/地区的多供应商路由、已批准备用认证通道和失败关闭策略。';

CREATE TABLE messaging.message_template (
    id                    uuid        NOT NULL DEFAULT gen_random_uuid(),
    template_code         text        NOT NULL,
    template_version      integer     NOT NULL,
    channel_code          text        NOT NULL,
    locale                text        NOT NULL,
    purpose_code          text        NOT NULL,
    subject_template      text        NULL,
    body_template         text        NOT NULL,
    variable_schema       jsonb       NOT NULL,
    content_hash          bytea       NOT NULL,
    release_id            uuid        NOT NULL,
    is_active             boolean     NOT NULL DEFAULT false,
    created_at            timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT pk_message_template PRIMARY KEY (id),
    CONSTRAINT uq_message_template_version UNIQUE (template_code, template_version, channel_code, locale),
    CONSTRAINT fk_message_template_release FOREIGN KEY (release_id) REFERENCES control.config_release(id),
    CONSTRAINT ck_message_template_channel CHECK (channel_code IN ('SMS', 'EMAIL', 'VOICE', 'PUSH', 'IN_APP')),
    CONSTRAINT ck_message_template_hash CHECK (octet_length(content_hash) = 32)
);
COMMENT ON TABLE messaging.message_template IS 'CAP-MSG-002：版本化、多语言、变量 Schema 校验且经控制面发布的消息模板。';

CREATE TABLE messaging.message_send (
    id                    uuid        NOT NULL DEFAULT gen_random_uuid(),
    public_id             text        NOT NULL,
    message_purpose       text        NOT NULL,
    channel_code          text        NOT NULL,
    template_id           uuid        NOT NULL,
    route_policy_id       uuid        NOT NULL,
    target_identifier_id  uuid        NULL,
    target_address_ciphertext bytea   NULL,
    target_blind_index    bytea       NOT NULL,
    user_id               uuid        NULL,
    tenant_id             uuid        NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
    client_id             uuid        NULL,
    challenge_id          uuid        NULL,
    idempotency_key       text        NOT NULL,
    variable_hash         bytea       NOT NULL,
    send_state            text        NOT NULL DEFAULT 'PENDING',
    provider_id           uuid        NULL,
    provider_message_ref_hash bytea   NULL,
    attempt_count         integer     NOT NULL DEFAULT 0,
    next_attempt_at       timestamptz NULL,
    sent_at               timestamptz NULL,
    delivered_at          timestamptz NULL,
    failed_at             timestamptz NULL,
    failure_code          text        NULL,
    expires_at            timestamptz NOT NULL,
    created_at            timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at            timestamptz NOT NULL DEFAULT clock_timestamp(),
    row_version           bigint      NOT NULL DEFAULT 1,
    CONSTRAINT pk_message_send PRIMARY KEY (id),
    CONSTRAINT uq_message_send_public_id UNIQUE (public_id),
    CONSTRAINT uq_message_send_idempotency UNIQUE (message_purpose, idempotency_key),
    CONSTRAINT fk_message_send_template FOREIGN KEY (template_id) REFERENCES messaging.message_template(id),
    CONSTRAINT fk_message_send_route FOREIGN KEY (route_policy_id) REFERENCES messaging.route_policy(id),
    CONSTRAINT fk_message_send_identifier FOREIGN KEY (target_identifier_id) REFERENCES iam.identifier(id),
    CONSTRAINT fk_message_send_user FOREIGN KEY (user_id) REFERENCES iam.user_account(id),
    CONSTRAINT fk_message_send_client FOREIGN KEY (client_id) REFERENCES oauth.client(id),
    CONSTRAINT fk_message_send_challenge FOREIGN KEY (challenge_id) REFERENCES authn.verification_challenge(id),
    CONSTRAINT fk_message_send_provider FOREIGN KEY (provider_id) REFERENCES messaging.provider(id),
    CONSTRAINT ck_message_send_channel CHECK (channel_code IN ('SMS', 'EMAIL', 'VOICE', 'PUSH', 'IN_APP')),
    CONSTRAINT ck_message_send_target CHECK (target_identifier_id IS NOT NULL OR target_address_ciphertext IS NOT NULL),
    CONSTRAINT ck_message_send_hash CHECK (octet_length(target_blind_index) = 32 AND octet_length(variable_hash) = 32),
    CONSTRAINT ck_message_send_state CHECK (send_state IN ('PENDING', 'SENDING', 'SENT', 'DELIVERED', 'FAILED', 'EXPIRED', 'CANCELLED')),
    CONSTRAINT ck_message_send_attempt CHECK (attempt_count >= 0),
    CONSTRAINT ck_message_send_delivery CHECK (send_state <> 'DELIVERED' OR delivered_at IS NOT NULL),
    CONSTRAINT ck_message_send_failure CHECK (send_state <> 'FAILED' OR (failed_at IS NOT NULL AND failure_code IS NOT NULL)),
    CONSTRAINT ck_message_send_expiry CHECK (expires_at > created_at)
);
COMMENT ON TABLE messaging.message_send IS 'CAP-MSG-004/005：不含验证码/正文秘密的幂等消息发送、加密目标、盲索引、供应商尝试和结果。';

CREATE TABLE messaging.delivery_receipt (
    id                    uuid        NOT NULL DEFAULT gen_random_uuid(),
    message_send_id       uuid        NOT NULL,
    provider_id           uuid        NOT NULL,
    provider_event_id_hash bytea      NOT NULL,
    receipt_kind          text        NOT NULL,
    provider_occurred_at  timestamptz NULL,
    payload_hash          bytea       NOT NULL,
    received_at           timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT pk_delivery_receipt PRIMARY KEY (id),
    CONSTRAINT uq_delivery_receipt UNIQUE (provider_id, provider_event_id_hash),
    CONSTRAINT fk_delivery_receipt_message FOREIGN KEY (message_send_id) REFERENCES messaging.message_send(id),
    CONSTRAINT fk_delivery_receipt_provider FOREIGN KEY (provider_id) REFERENCES messaging.provider(id),
    CONSTRAINT ck_delivery_receipt_kind CHECK (receipt_kind IN ('ACCEPTED', 'SENT', 'DELIVERED', 'BOUNCED', 'REJECTED', 'COMPLAINT', 'UNSUBSCRIBED')),
    CONSTRAINT ck_delivery_receipt_hash CHECK (octet_length(provider_event_id_hash) = 32 AND octet_length(payload_hash) = 32)
);
COMMENT ON TABLE messaging.delivery_receipt IS '消息供应商回执的幂等摘要、类型和源端时间；原始回执按数据目录另行受控保留。';

CREATE TABLE messaging.reachability (
    identifier_id         uuid        NOT NULL,
    channel_code          text        NOT NULL,
    reachability_state    text        NOT NULL DEFAULT 'UNKNOWN',
    hard_failure_count    integer     NOT NULL DEFAULT 0,
    soft_failure_count    integer     NOT NULL DEFAULT 0,
    last_success_at       timestamptz NULL,
    last_failure_at       timestamptz NULL,
    suppressed_until      timestamptz NULL,
    updated_at            timestamptz NOT NULL DEFAULT clock_timestamp(),
    row_version           bigint      NOT NULL DEFAULT 1,
    CONSTRAINT pk_reachability PRIMARY KEY (identifier_id, channel_code),
    CONSTRAINT fk_reachability_identifier FOREIGN KEY (identifier_id) REFERENCES iam.identifier(id),
    CONSTRAINT ck_reachability_channel CHECK (channel_code IN ('SMS', 'EMAIL', 'VOICE', 'PUSH')),
    CONSTRAINT ck_reachability_state CHECK (reachability_state IN ('UNKNOWN', 'REACHABLE', 'SOFT_BOUNCE', 'HARD_BOUNCE', 'COMPLAINT', 'SUPPRESSED')),
    CONSTRAINT ck_reachability_count CHECK (hard_failure_count >= 0 AND soft_failure_count >= 0)
);
COMMENT ON TABLE messaging.reachability IS 'CAP-MSG-006：标识通道可达性、退信、投诉和抑制水位；不改变 Identifier 所有权状态。';

CREATE TABLE messaging.content_compliance_rule (
    id                    uuid        NOT NULL DEFAULT gen_random_uuid(),
    rule_code             text        NOT NULL,
    rule_version          integer     NOT NULL,
    channel_code          text        NOT NULL,
    region_code           text        NOT NULL,
    message_purpose       text        NOT NULL,
    prohibited_patterns_hash bytea    NOT NULL,
    required_sender_identity text     NULL,
    required_unsubscribe_marker boolean NOT NULL DEFAULT false,
    regulatory_filing_ref text        NULL,
    release_id            uuid        NOT NULL,
    is_active             boolean     NOT NULL DEFAULT false,
    effective_at          timestamptz NOT NULL,
    retired_at            timestamptz NULL,
    CONSTRAINT pk_content_compliance_rule PRIMARY KEY (id),
    CONSTRAINT uq_content_compliance_rule_version UNIQUE (rule_code, rule_version),
    CONSTRAINT fk_content_compliance_rule_release FOREIGN KEY (release_id) REFERENCES control.config_release(id),
    CONSTRAINT ck_content_compliance_rule_channel CHECK (channel_code IN ('SMS', 'EMAIL', 'VOICE', 'PUSH', 'IN_APP')),
    CONSTRAINT ck_content_compliance_rule_hash CHECK (octet_length(prohibited_patterns_hash) = 32),
    CONSTRAINT ck_content_compliance_rule_window CHECK (retired_at IS NULL OR retired_at > effective_at)
);
COMMENT ON TABLE messaging.content_compliance_rule IS 'CAP-MSG-006/011：按通道、地区、用途执行敏感词、发送方、退订标识和监管报备的版本化规则。';

CREATE TABLE messaging.provider_metric (
    id                    uuid        NOT NULL DEFAULT gen_random_uuid(),
    provider_id           uuid        NOT NULL,
    channel_code          text        NOT NULL,
    region_code           text        NOT NULL,
    template_code         text        NULL,
    metric_window_start   timestamptz NOT NULL,
    metric_window_end     timestamptz NOT NULL,
    submitted_count       bigint      NOT NULL DEFAULT 0,
    delivered_count       bigint      NOT NULL DEFAULT 0,
    failed_count          bigint      NOT NULL DEFAULT 0,
    latency_p95_ms        numeric(12,3) NULL,
    unit_cost             numeric(18,6) NULL,
    currency_code         text        NULL,
    calculated_at         timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT pk_provider_metric PRIMARY KEY (id),
    CONSTRAINT uq_provider_metric UNIQUE NULLS NOT DISTINCT (provider_id, region_code, template_code, metric_window_start, metric_window_end),
    CONSTRAINT fk_provider_metric_provider FOREIGN KEY (provider_id) REFERENCES messaging.provider(id),
    CONSTRAINT ck_provider_metric_channel CHECK (channel_code IN ('SMS', 'EMAIL', 'VOICE', 'PUSH', 'IN_APP')),
    CONSTRAINT ck_provider_metric_window CHECK (metric_window_end > metric_window_start),
    CONSTRAINT ck_provider_metric_count CHECK (submitted_count >= 0 AND delivered_count >= 0 AND failed_count >= 0 AND delivered_count + failed_count <= submitted_count),
    CONSTRAINT ck_provider_metric_latency CHECK (latency_p95_ms IS NULL OR latency_p95_ms >= 0),
    CONSTRAINT ck_provider_metric_cost CHECK ((unit_cost IS NULL) = (currency_code IS NULL) AND (unit_cost IS NULL OR unit_cost >= 0))
);
COMMENT ON TABLE messaging.provider_metric IS 'CAP-MSG-008 / CAP-OBS-016：供应商、地区、模板维度的送达率、P95 时延、单价和成本归属聚合。';

CREATE UNIQUE INDEX ux_event_schema_active ON integration.event_schema(event_type) WHERE is_active;
CREATE INDEX ix_outbox_publish ON integration.outbox_event(available_at, id) WHERE publish_state IN ('PENDING', 'FAILED');
CREATE INDEX ix_outbox_aggregate ON integration.outbox_event(aggregate_kind, aggregate_ref, aggregate_version);
CREATE INDEX ix_webhook_delivery_retry ON integration.webhook_delivery(next_attempt_at) WHERE delivery_state IN ('PENDING', 'FAILED');
CREATE INDEX ix_audit_trace ON audit.audit_event(trace_id, occurred_at);
CREATE INDEX ix_audit_object ON audit.audit_event(object_kind, object_ref, occurred_at DESC);
CREATE INDEX ix_audit_occurred_brin ON audit.audit_event USING brin(occurred_at);
CREATE INDEX ix_data_access_occurred_brin ON audit.data_access_event USING brin(accessed_at);
CREATE INDEX ix_message_send_retry ON messaging.message_send(next_attempt_at) WHERE send_state IN ('PENDING', 'FAILED');
CREATE INDEX ix_message_target ON messaging.message_send(target_blind_index, created_at DESC);
CREATE INDEX ix_provider_metric_window ON messaging.provider_metric(provider_id, metric_window_start DESC);

CREATE OR REPLACE FUNCTION integration.fn_webhook_consent_guard()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.subscription_state = 'ACTIVE' AND NEW.consent_aggregate_id IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM privacy.consent_aggregate a
         WHERE a.id = NEW.consent_aggregate_id AND a.current_epoch = NEW.consent_epoch
    ) THEN
        RAISE EXCEPTION 'CONSENT_EPOCH_STALE' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;
COMMENT ON FUNCTION integration.fn_webhook_consent_guard() IS '依赖 Consent 的 Webhook 激活时必须绑定聚合当前 epoch。';

CREATE OR REPLACE FUNCTION audit.fn_audit_chain_guard()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE v_previous bytea; v_sequence bigint;
BEGIN
    SELECT event_hash, chain_sequence INTO v_previous, v_sequence
      FROM audit.audit_event
     WHERE chain_partition = NEW.chain_partition
     ORDER BY chain_sequence DESC LIMIT 1 FOR UPDATE;
    IF NOT FOUND THEN
        IF NEW.chain_sequence <> 1 OR NEW.previous_event_hash IS NOT NULL THEN
            RAISE EXCEPTION 'AUDIT_CHAIN_INVALID_FIRST' USING ERRCODE = '23514';
        END IF;
    ELSE
        IF NEW.chain_sequence <> v_sequence + 1 OR NEW.previous_event_hash IS DISTINCT FROM v_previous THEN
            RAISE EXCEPTION 'AUDIT_CHAIN_BROKEN' USING ERRCODE = '23514';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;
COMMENT ON FUNCTION audit.fn_audit_chain_guard() IS '按 chain_partition 串行校验审计序号和 previous hash，阻断链断裂。';

CREATE OR REPLACE FUNCTION integration.fn_outbox_immutable_guard()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN RAISE EXCEPTION 'OUTBOX_DELETE_FORBIDDEN' USING ERRCODE = '55000'; END IF;
    IF NEW.event_id <> OLD.event_id OR NEW.event_type <> OLD.event_type OR NEW.schema_version <> OLD.schema_version
       OR NEW.aggregate_kind <> OLD.aggregate_kind OR NEW.aggregate_ref <> OLD.aggregate_ref OR NEW.aggregate_version <> OLD.aggregate_version
       OR NEW.payload_hash <> OLD.payload_hash OR NEW.payload <> OLD.payload OR NEW.occurred_at <> OLD.occurred_at THEN
        RAISE EXCEPTION 'OUTBOX_EVENT_IMMUTABLE' USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END;
$$;
COMMENT ON FUNCTION integration.fn_outbox_immutable_guard() IS 'Outbox 仅允许更新投递元数据，事件身份、顺序、正文和摘要不可修改且禁止删除。';

CREATE OR REPLACE FUNCTION audit.fn_audit_outbox_immutable_guard()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN RAISE EXCEPTION 'AUDIT_OUTBOX_DELETE_FORBIDDEN' USING ERRCODE = '55000'; END IF;
    IF NEW.audit_event_id <> OLD.audit_event_id OR NEW.audit_type <> OLD.audit_type
       OR NEW.event_payload_ciphertext <> OLD.event_payload_ciphertext OR NEW.payload_hash <> OLD.payload_hash
       OR NEW.encryption_key_ref <> OLD.encryption_key_ref THEN
        RAISE EXCEPTION 'AUDIT_OUTBOX_PAYLOAD_IMMUTABLE' USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END;
$$;
COMMENT ON FUNCTION audit.fn_audit_outbox_immutable_guard() IS '本地审计 Outbox 仅允许推进远端持久化状态，证据密文、摘要和密钥引用不可改删。';

CREATE OR REPLACE FUNCTION messaging.fn_message_send_guard()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
          FROM messaging.message_template t
          JOIN messaging.route_policy r ON r.id = NEW.route_policy_id
         WHERE t.id = NEW.template_id AND t.is_active
           AND r.is_active
           AND t.channel_code = NEW.channel_code
           AND r.channel_code = NEW.channel_code
           AND t.purpose_code = NEW.message_purpose
           AND r.purpose_code = NEW.message_purpose
    ) THEN
        RAISE EXCEPTION 'MESSAGE_TEMPLATE_OR_ROUTE_INVALID' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;
COMMENT ON FUNCTION messaging.fn_message_send_guard() IS '发送前校验模板和路由均已激活，且通道与用途精确一致。';

CREATE TRIGGER trg_outbox_immutable BEFORE UPDATE OR DELETE ON integration.outbox_event FOR EACH ROW EXECUTE FUNCTION integration.fn_outbox_immutable_guard();
CREATE TRIGGER trg_webhook_subscription_public_id BEFORE INSERT ON integration.webhook_subscription FOR EACH ROW EXECUTE FUNCTION core.fn_register_public_id('WEBHOOK_SUBSCRIPTION');
CREATE TRIGGER trg_webhook_subscription_consent BEFORE INSERT OR UPDATE ON integration.webhook_subscription FOR EACH ROW EXECUTE FUNCTION integration.fn_webhook_consent_guard();
CREATE TRIGGER trg_webhook_subscription_touch BEFORE UPDATE ON integration.webhook_subscription FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();
CREATE TRIGGER trg_webhook_subscription_version BEFORE UPDATE ON integration.webhook_subscription FOR EACH ROW EXECUTE FUNCTION core.fn_increment_row_version();
CREATE TRIGGER trg_webhook_delivery_public_id BEFORE INSERT ON integration.webhook_delivery FOR EACH ROW EXECUTE FUNCTION core.fn_register_public_id('WEBHOOK_DELIVERY');
CREATE TRIGGER trg_replay_public_id BEFORE INSERT ON integration.event_replay_request FOR EACH ROW EXECUTE FUNCTION core.fn_register_public_id('EVENT_REPLAY');
CREATE TRIGGER trg_consumer_watermark_touch BEFORE UPDATE ON integration.consumer_watermark FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();
CREATE TRIGGER trg_consumer_watermark_version BEFORE UPDATE ON integration.consumer_watermark FOR EACH ROW EXECUTE FUNCTION core.fn_increment_row_version();
CREATE TRIGGER trg_audit_outbox_immutable BEFORE UPDATE OR DELETE ON audit.audit_outbox FOR EACH ROW EXECUTE FUNCTION audit.fn_audit_outbox_immutable_guard();
CREATE TRIGGER trg_audit_event_chain BEFORE INSERT ON audit.audit_event FOR EACH ROW EXECUTE FUNCTION audit.fn_audit_chain_guard();
CREATE TRIGGER trg_audit_event_append_only BEFORE UPDATE OR DELETE ON audit.audit_event FOR EACH STATEMENT EXECUTE FUNCTION core.fn_append_only();
CREATE TRIGGER trg_audit_seal_append_only BEFORE UPDATE OR DELETE ON audit.audit_seal FOR EACH STATEMENT EXECUTE FUNCTION core.fn_append_only();
CREATE TRIGGER trg_data_access_append_only BEFORE UPDATE OR DELETE ON audit.data_access_event FOR EACH STATEMENT EXECUTE FUNCTION core.fn_append_only();
CREATE TRIGGER trg_provider_touch BEFORE UPDATE ON messaging.provider FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();
CREATE TRIGGER trg_provider_version BEFORE UPDATE ON messaging.provider FOR EACH ROW EXECUTE FUNCTION core.fn_increment_row_version();
CREATE TRIGGER trg_message_send_public_id BEFORE INSERT ON messaging.message_send FOR EACH ROW EXECUTE FUNCTION core.fn_register_public_id('MESSAGE_SEND');
CREATE TRIGGER trg_message_send_guard BEFORE INSERT ON messaging.message_send FOR EACH ROW EXECUTE FUNCTION messaging.fn_message_send_guard();
CREATE TRIGGER trg_message_send_touch BEFORE UPDATE ON messaging.message_send FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();
CREATE TRIGGER trg_message_send_version BEFORE UPDATE ON messaging.message_send FOR EACH ROW EXECUTE FUNCTION core.fn_increment_row_version();
CREATE TRIGGER trg_delivery_receipt_append_only BEFORE UPDATE OR DELETE ON messaging.delivery_receipt FOR EACH STATEMENT EXECUTE FUNCTION core.fn_append_only();
CREATE TRIGGER trg_reachability_touch BEFORE UPDATE ON messaging.reachability FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();
CREATE TRIGGER trg_reachability_version BEFORE UPDATE ON messaging.reachability FOR EACH ROW EXECUTE FUNCTION core.fn_increment_row_version();
CREATE TRIGGER trg_provider_metric_append_only BEFORE UPDATE OR DELETE ON messaging.provider_metric FOR EACH STATEMENT EXECUTE FUNCTION core.fn_append_only();

SELECT core.fn_register_migration('060', '事件、Outbox、Webhook、审计、消息投递与可达性', NULLIF(current_setting('kuc.migration_sha256', true), ''));
COMMIT;
