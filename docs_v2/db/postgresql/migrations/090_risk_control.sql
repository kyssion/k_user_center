-- Risk evidence, control-plane governance and cryptographic metadata.
-- Cross-row separation-of-duty, last-valid-key and release gate checks are
-- deferred to 110_constraints_functions.sql.

BEGIN;

CREATE TABLE public.risk_signals (
    risk_signal_pk bigint GENERATED ALWAYS AS IDENTITY,
    risk_signal_id uuid NOT NULL DEFAULT pg_catalog.gen_random_uuid(),
    source_code text COLLATE "C" NOT NULL,
    source_event_key text COLLATE "C" NOT NULL,
    signal_type text COLLATE "C" NOT NULL,
    confidence numeric(5,4) NOT NULL,
    severity text COLLATE "C" NOT NULL,
    payload_schema_version integer NOT NULL,
    payload jsonb NOT NULL,
    payload_hash bytea NOT NULL,
    occurred_at timestamptz NOT NULL,
    received_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    retention_until timestamptz NOT NULL,
    CONSTRAINT risk_signals_pkey PRIMARY KEY (risk_signal_pk),
    CONSTRAINT risk_signals_id_key UNIQUE (risk_signal_id),
    CONSTRAINT risk_signals_source_event_key UNIQUE (source_code, source_event_key),
    CONSTRAINT risk_signals_id_v4_ck CHECK (public.iam_uuid_is_v4(risk_signal_id)),
    CONSTRAINT risk_signals_source_ck CHECK (
        pg_catalog.length(source_code) BETWEEN 1 AND 96
        AND source_code ~ '^[A-Z][A-Z0-9_.:-]*$'
    ),
    CONSTRAINT risk_signals_source_event_ck CHECK (
        pg_catalog.length(source_event_key) BETWEEN 1 AND 255
        AND source_event_key ~ '^[A-Za-z0-9][A-Za-z0-9_.:/-]*$'
    ),
    CONSTRAINT risk_signals_type_ck CHECK (
        pg_catalog.length(signal_type) BETWEEN 1 AND 96
        AND signal_type ~ '^[A-Z][A-Z0-9_.:-]*$'
    ),
    CONSTRAINT risk_signals_confidence_ck CHECK (confidence BETWEEN 0 AND 1),
    CONSTRAINT risk_signals_severity_ck CHECK (
        severity IN ('INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL')
    ),
    CONSTRAINT risk_signals_payload_ck CHECK (
        payload_schema_version > 0 AND pg_catalog.jsonb_typeof(payload) = 'object'
        AND pg_catalog.octet_length(payload::text) <= 262144
    ),
    CONSTRAINT risk_signals_hash_ck CHECK (pg_catalog.octet_length(payload_hash) = 32),
    CONSTRAINT risk_signals_time_ck CHECK (
        occurred_at <= received_at AND retention_until > received_at
    )
);

COMMENT ON TABLE public.risk_signals IS
    'Append-only normalized risk signals with bounded non-credential payload, confidence, provenance and retention; S3.';

CREATE INDEX risk_signals_type_time_idx
    ON public.risk_signals (signal_type, occurred_at DESC);
CREATE INDEX risk_signals_retention_idx
    ON public.risk_signals (retention_until, risk_signal_pk);

CREATE TRIGGER risk_signals_append_only_trg
BEFORE UPDATE OR DELETE ON public.risk_signals
FOR EACH ROW EXECUTE FUNCTION public.iam_reject_row_mutation();

CREATE TABLE public.risk_signal_targets (
    risk_signal_target_pk bigint GENERATED ALWAYS AS IDENTITY,
    risk_signal_pk bigint NOT NULL,
    target_type text COLLATE "C" NOT NULL,
    principal_pk bigint,
    tenant_pk bigint,
    client_pk bigint,
    resource_pk bigint,
    target_key_digest bytea,
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    CONSTRAINT risk_signal_targets_pkey PRIMARY KEY (risk_signal_target_pk),
    CONSTRAINT risk_signal_targets_signal_fk FOREIGN KEY (risk_signal_pk)
        REFERENCES public.risk_signals (risk_signal_pk) ON DELETE RESTRICT,
    CONSTRAINT risk_signal_targets_principal_fk FOREIGN KEY (principal_pk)
        REFERENCES public.iam_principals (principal_pk) ON DELETE RESTRICT,
    CONSTRAINT risk_signal_targets_tenant_fk FOREIGN KEY (tenant_pk)
        REFERENCES public.org_tenants (tenant_pk) ON DELETE RESTRICT,
    CONSTRAINT risk_signal_targets_client_fk FOREIGN KEY (client_pk)
        REFERENCES public.app_clients (client_pk) ON DELETE RESTRICT,
    CONSTRAINT risk_signal_targets_resource_fk FOREIGN KEY (resource_pk)
        REFERENCES public.authz_resources (resource_pk) ON DELETE RESTRICT,
    CONSTRAINT risk_signal_targets_shape_ck CHECK (
        (target_type = 'PRINCIPAL' AND principal_pk IS NOT NULL AND tenant_pk IS NULL
            AND client_pk IS NULL AND resource_pk IS NULL AND target_key_digest IS NULL)
        OR (target_type = 'TENANT' AND principal_pk IS NULL AND tenant_pk IS NOT NULL
            AND client_pk IS NULL AND resource_pk IS NULL AND target_key_digest IS NULL)
        OR (target_type = 'CLIENT' AND principal_pk IS NULL AND tenant_pk IS NULL
            AND client_pk IS NOT NULL AND resource_pk IS NULL AND target_key_digest IS NULL)
        OR (target_type = 'RESOURCE' AND principal_pk IS NULL AND tenant_pk IS NULL
            AND client_pk IS NULL AND resource_pk IS NOT NULL AND target_key_digest IS NULL)
        OR (target_type IN ('DEVICE', 'NETWORK', 'IDENTIFIER') AND principal_pk IS NULL
            AND tenant_pk IS NULL AND client_pk IS NULL AND resource_pk IS NULL
            AND target_key_digest IS NOT NULL AND pg_catalog.octet_length(target_key_digest) = 32)
    )
);

COMMENT ON TABLE public.risk_signal_targets IS
    'Typed relational targets for a risk signal; device, network and identifier targets use keyed digests; S3.';

CREATE INDEX risk_signal_targets_principal_idx
    ON public.risk_signal_targets (principal_pk, risk_signal_pk)
    WHERE principal_pk IS NOT NULL;
CREATE INDEX risk_signal_targets_tenant_idx
    ON public.risk_signal_targets (tenant_pk, risk_signal_pk)
    WHERE tenant_pk IS NOT NULL;

CREATE TABLE public.risk_rules (
    risk_rule_pk bigint GENERATED ALWAYS AS IDENTITY,
    risk_rule_id uuid NOT NULL DEFAULT pg_catalog.gen_random_uuid(),
    rule_code text COLLATE "C" NOT NULL,
    scope_node_pk bigint NOT NULL,
    state text COLLATE "C" NOT NULL DEFAULT 'DRAFT',
    row_version bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    CONSTRAINT risk_rules_pkey PRIMARY KEY (risk_rule_pk),
    CONSTRAINT risk_rules_id_key UNIQUE (risk_rule_id),
    CONSTRAINT risk_rules_code_key UNIQUE (scope_node_pk, rule_code),
    CONSTRAINT risk_rules_id_v4_ck CHECK (public.iam_uuid_is_v4(risk_rule_id)),
    CONSTRAINT risk_rules_scope_fk FOREIGN KEY (scope_node_pk)
        REFERENCES public.authz_scope_nodes (scope_node_pk) ON DELETE RESTRICT,
    CONSTRAINT risk_rules_code_ck CHECK (
        pg_catalog.length(rule_code) BETWEEN 1 AND 96
        AND rule_code ~ '^[A-Z][A-Z0-9_.:-]*$'
    ),
    CONSTRAINT risk_rules_state_ck CHECK (
        state IN ('DRAFT', 'ACTIVE', 'SUSPENDED', 'RETIRED')
    ),
    CONSTRAINT risk_rules_version_ck CHECK (row_version > 0),
    CONSTRAINT risk_rules_time_ck CHECK (updated_at >= created_at)
);

COMMENT ON TABLE public.risk_rules IS
    'Stable risk-rule identity and scope; executable definitions live in immutable versions; S2.';

CREATE INDEX risk_rules_scope_state_idx
    ON public.risk_rules (scope_node_pk, state, rule_code);

CREATE TABLE public.risk_rule_versions (
    risk_rule_version_pk bigint GENERATED ALWAYS AS IDENTITY,
    risk_rule_version_id uuid NOT NULL DEFAULT pg_catalog.gen_random_uuid(),
    risk_rule_pk bigint NOT NULL,
    version_no bigint NOT NULL,
    schema_version integer NOT NULL,
    rule_ast jsonb NOT NULL,
    content_hash bytea NOT NULL,
    state text COLLATE "C" NOT NULL DEFAULT 'DRAFT',
    validated_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    CONSTRAINT risk_rule_versions_pkey PRIMARY KEY (risk_rule_version_pk),
    CONSTRAINT risk_rule_versions_id_key UNIQUE (risk_rule_version_id),
    CONSTRAINT risk_rule_versions_number_key UNIQUE (risk_rule_pk, version_no),
    CONSTRAINT risk_rule_versions_hash_key UNIQUE (content_hash),
    CONSTRAINT risk_rule_versions_id_v4_ck CHECK (public.iam_uuid_is_v4(risk_rule_version_id)),
    CONSTRAINT risk_rule_versions_rule_fk FOREIGN KEY (risk_rule_pk)
        REFERENCES public.risk_rules (risk_rule_pk) ON DELETE RESTRICT,
    CONSTRAINT risk_rule_versions_number_ck CHECK (version_no > 0),
    CONSTRAINT risk_rule_versions_ast_ck CHECK (
        schema_version > 0 AND pg_catalog.jsonb_typeof(rule_ast) = 'object'
        AND pg_catalog.octet_length(rule_ast::text) <= 524288
    ),
    CONSTRAINT risk_rule_versions_hash_ck CHECK (pg_catalog.octet_length(content_hash) = 32),
    CONSTRAINT risk_rule_versions_state_ck CHECK (
        state IN ('DRAFT', 'VALIDATED', 'REJECTED', 'RETIRED')
    ),
    CONSTRAINT risk_rule_versions_validation_ck CHECK (
        (state = 'DRAFT' AND validated_at IS NULL)
        OR (state <> 'DRAFT' AND validated_at IS NOT NULL)
    )
);

COMMENT ON TABLE public.risk_rule_versions IS
    'Immutable, schema-versioned risk rule AST and canonical hash; S2.';

CREATE INDEX risk_rule_versions_rule_state_idx
    ON public.risk_rule_versions (risk_rule_pk, state, version_no DESC);

CREATE TRIGGER risk_rule_versions_immutable_trg
BEFORE UPDATE ON public.risk_rule_versions
FOR EACH ROW
WHEN (OLD.state <> 'DRAFT')
EXECUTE FUNCTION public.iam_reject_column_changes(
    'risk_rule_version_pk', 'risk_rule_version_id', 'risk_rule_pk',
    'version_no', 'schema_version', 'rule_ast', 'content_hash',
    'validated_at', 'created_at'
);

CREATE TABLE public.risk_models (
    risk_model_pk bigint GENERATED ALWAYS AS IDENTITY,
    risk_model_id uuid NOT NULL DEFAULT pg_catalog.gen_random_uuid(),
    model_code text COLLATE "C" NOT NULL,
    model_type text COLLATE "C" NOT NULL,
    owner_principal_pk bigint NOT NULL,
    state text COLLATE "C" NOT NULL DEFAULT 'DRAFT',
    row_version bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    CONSTRAINT risk_models_pkey PRIMARY KEY (risk_model_pk),
    CONSTRAINT risk_models_id_key UNIQUE (risk_model_id),
    CONSTRAINT risk_models_code_key UNIQUE (model_code),
    CONSTRAINT risk_models_id_v4_ck CHECK (public.iam_uuid_is_v4(risk_model_id)),
    CONSTRAINT risk_models_owner_fk FOREIGN KEY (owner_principal_pk)
        REFERENCES public.iam_principals (principal_pk) ON DELETE RESTRICT,
    CONSTRAINT risk_models_code_ck CHECK (
        pg_catalog.length(model_code) BETWEEN 1 AND 96
        AND model_code ~ '^[A-Z][A-Z0-9_.:-]*$'
    ),
    CONSTRAINT risk_models_type_ck CHECK (
        model_type IN ('STATISTICAL', 'MACHINE_LEARNING', 'ENSEMBLE', 'VENDOR')
    ),
    CONSTRAINT risk_models_state_ck CHECK (
        state IN ('DRAFT', 'ACTIVE', 'SUSPENDED', 'RETIRED')
    ),
    CONSTRAINT risk_models_version_ck CHECK (row_version > 0),
    CONSTRAINT risk_models_time_ck CHECK (updated_at >= created_at)
);

COMMENT ON TABLE public.risk_models IS
    'Governed risk-model identity, type and owner; model binaries stay outside PostgreSQL; S2.';

CREATE INDEX risk_models_owner_state_idx
    ON public.risk_models (owner_principal_pk, state, model_code);

CREATE TABLE public.risk_model_versions (
    risk_model_version_pk bigint GENERATED ALWAYS AS IDENTITY,
    risk_model_version_id uuid NOT NULL DEFAULT pg_catalog.gen_random_uuid(),
    risk_model_pk bigint NOT NULL,
    version_no bigint NOT NULL,
    artifact_reference text COLLATE "C" NOT NULL,
    artifact_hash bytea NOT NULL,
    feature_schema_version integer NOT NULL,
    feature_schema jsonb NOT NULL,
    metrics_schema_version integer NOT NULL,
    validation_metrics jsonb NOT NULL,
    state text COLLATE "C" NOT NULL DEFAULT 'DRAFT',
    validated_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    CONSTRAINT risk_model_versions_pkey PRIMARY KEY (risk_model_version_pk),
    CONSTRAINT risk_model_versions_id_key UNIQUE (risk_model_version_id),
    CONSTRAINT risk_model_versions_number_key UNIQUE (risk_model_pk, version_no),
    CONSTRAINT risk_model_versions_hash_key UNIQUE (artifact_hash),
    CONSTRAINT risk_model_versions_id_v4_ck CHECK (public.iam_uuid_is_v4(risk_model_version_id)),
    CONSTRAINT risk_model_versions_model_fk FOREIGN KEY (risk_model_pk)
        REFERENCES public.risk_models (risk_model_pk) ON DELETE RESTRICT,
    CONSTRAINT risk_model_versions_number_ck CHECK (version_no > 0),
    CONSTRAINT risk_model_versions_reference_ck CHECK (
        pg_catalog.length(artifact_reference) BETWEEN 1 AND 1024
    ),
    CONSTRAINT risk_model_versions_hash_ck CHECK (pg_catalog.octet_length(artifact_hash) = 32),
    CONSTRAINT risk_model_versions_feature_schema_ck CHECK (
        feature_schema_version > 0 AND pg_catalog.jsonb_typeof(feature_schema) = 'object'
        AND pg_catalog.octet_length(feature_schema::text) <= 262144
    ),
    CONSTRAINT risk_model_versions_metrics_ck CHECK (
        metrics_schema_version > 0 AND pg_catalog.jsonb_typeof(validation_metrics) = 'object'
        AND pg_catalog.octet_length(validation_metrics::text) <= 262144
    ),
    CONSTRAINT risk_model_versions_state_ck CHECK (
        state IN ('DRAFT', 'VALIDATED', 'REJECTED', 'RETIRED')
    ),
    CONSTRAINT risk_model_versions_validation_ck CHECK (
        (state = 'DRAFT' AND validated_at IS NULL)
        OR (state <> 'DRAFT' AND validated_at IS NOT NULL)
    )
);

COMMENT ON TABLE public.risk_model_versions IS
    'Immutable model artifact reference, feature schema, validation metrics and digest; S2/S3.';

CREATE INDEX risk_model_versions_model_state_idx
    ON public.risk_model_versions (risk_model_pk, state, version_no DESC);

CREATE TRIGGER risk_model_versions_immutable_trg
BEFORE UPDATE ON public.risk_model_versions
FOR EACH ROW
WHEN (OLD.state <> 'DRAFT')
EXECUTE FUNCTION public.iam_reject_column_changes(
    'risk_model_version_pk', 'risk_model_version_id', 'risk_model_pk',
    'version_no', 'artifact_reference', 'artifact_hash',
    'feature_schema_version', 'feature_schema', 'metrics_schema_version',
    'validation_metrics', 'validated_at', 'created_at'
);

CREATE TABLE public.risk_assessments (
    risk_assessment_pk bigint GENERATED ALWAYS AS IDENTITY,
    risk_assessment_id uuid NOT NULL DEFAULT pg_catalog.gen_random_uuid(),
    subject_principal_pk bigint,
    actor_principal_pk bigint,
    tenant_pk bigint,
    transaction_id uuid,
    operation_code text COLLATE "C" NOT NULL,
    score numeric(7,4) NOT NULL,
    risk_level text COLLATE "C" NOT NULL,
    decision text COLLATE "C" NOT NULL,
    risk_rule_version_pk bigint,
    risk_model_version_pk bigint,
    explanation_schema_version integer NOT NULL,
    explanation jsonb NOT NULL,
    input_digest bytea NOT NULL,
    assessed_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    CONSTRAINT risk_assessments_pkey PRIMARY KEY (risk_assessment_pk),
    CONSTRAINT risk_assessments_id_key UNIQUE (risk_assessment_id),
    CONSTRAINT risk_assessments_id_v4_ck CHECK (public.iam_uuid_is_v4(risk_assessment_id)),
    CONSTRAINT risk_assessments_subject_fk FOREIGN KEY (subject_principal_pk)
        REFERENCES public.iam_principals (principal_pk) ON DELETE RESTRICT,
    CONSTRAINT risk_assessments_actor_fk FOREIGN KEY (actor_principal_pk)
        REFERENCES public.iam_principals (principal_pk) ON DELETE RESTRICT,
    CONSTRAINT risk_assessments_tenant_fk FOREIGN KEY (tenant_pk)
        REFERENCES public.org_tenants (tenant_pk) ON DELETE RESTRICT,
    CONSTRAINT risk_assessments_rule_version_fk FOREIGN KEY (risk_rule_version_pk)
        REFERENCES public.risk_rule_versions (risk_rule_version_pk) ON DELETE RESTRICT,
    CONSTRAINT risk_assessments_model_version_fk FOREIGN KEY (risk_model_version_pk)
        REFERENCES public.risk_model_versions (risk_model_version_pk) ON DELETE RESTRICT,
    CONSTRAINT risk_assessments_transaction_v4_ck CHECK (
        transaction_id IS NULL OR public.iam_uuid_is_v4(transaction_id)
    ),
    CONSTRAINT risk_assessments_operation_ck CHECK (
        pg_catalog.length(operation_code) BETWEEN 1 AND 96
        AND operation_code ~ '^[A-Z][A-Z0-9_.:-]*$'
    ),
    CONSTRAINT risk_assessments_score_ck CHECK (score BETWEEN 0 AND 100),
    CONSTRAINT risk_assessments_level_ck CHECK (
        risk_level IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')
    ),
    CONSTRAINT risk_assessments_decision_ck CHECK (
        decision IN ('ALLOW', 'CHALLENGE', 'STEP_UP', 'WAIT', 'DENY', 'FREEZE', 'REVIEW')
    ),
    CONSTRAINT risk_assessments_evaluator_ck CHECK (
        risk_rule_version_pk IS NOT NULL OR risk_model_version_pk IS NOT NULL
    ),
    CONSTRAINT risk_assessments_explanation_ck CHECK (
        explanation_schema_version > 0 AND pg_catalog.jsonb_typeof(explanation) = 'object'
        AND pg_catalog.octet_length(explanation::text) <= 131072
    ),
    CONSTRAINT risk_assessments_input_digest_ck CHECK (pg_catalog.octet_length(input_digest) = 32),
    CONSTRAINT risk_assessments_time_ck CHECK (
        assessed_at <= created_at AND expires_at > assessed_at
    )
);

COMMENT ON TABLE public.risk_assessments IS
    'Immutable risk conclusion for an operation with rule/model versions, score, disposition recommendation and explanation; S3.';

CREATE INDEX risk_assessments_subject_time_idx
    ON public.risk_assessments (subject_principal_pk, assessed_at DESC)
    WHERE subject_principal_pk IS NOT NULL;
CREATE INDEX risk_assessments_transaction_idx
    ON public.risk_assessments (transaction_id)
    WHERE transaction_id IS NOT NULL;

CREATE TRIGGER risk_assessments_append_only_trg
BEFORE UPDATE OR DELETE ON public.risk_assessments
FOR EACH ROW EXECUTE FUNCTION public.iam_reject_row_mutation();

CREATE TABLE public.risk_assessment_signals (
    risk_assessment_signal_pk bigint GENERATED ALWAYS AS IDENTITY,
    risk_assessment_pk bigint NOT NULL,
    risk_signal_pk bigint NOT NULL,
    weight numeric(8,5) NOT NULL,
    contribution numeric(9,4) NOT NULL,
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    CONSTRAINT risk_assessment_signals_pkey PRIMARY KEY (risk_assessment_signal_pk),
    CONSTRAINT risk_assessment_signals_member_key UNIQUE (risk_assessment_pk, risk_signal_pk),
    CONSTRAINT risk_assessment_signals_assessment_fk FOREIGN KEY (risk_assessment_pk)
        REFERENCES public.risk_assessments (risk_assessment_pk) ON DELETE RESTRICT,
    CONSTRAINT risk_assessment_signals_signal_fk FOREIGN KEY (risk_signal_pk)
        REFERENCES public.risk_signals (risk_signal_pk) ON DELETE RESTRICT,
    CONSTRAINT risk_assessment_signals_weight_ck CHECK (weight BETWEEN -100 AND 100),
    CONSTRAINT risk_assessment_signals_contribution_ck CHECK (contribution BETWEEN -10000 AND 10000)
);

COMMENT ON TABLE public.risk_assessment_signals IS
    'Relational signal inputs, weights and contributions used by an immutable assessment; S3.';

CREATE INDEX risk_assessment_signals_signal_idx
    ON public.risk_assessment_signals (risk_signal_pk, risk_assessment_pk);

CREATE TABLE public.risk_dispositions (
    risk_disposition_pk bigint GENERATED ALWAYS AS IDENTITY,
    risk_disposition_id uuid NOT NULL DEFAULT pg_catalog.gen_random_uuid(),
    risk_assessment_pk bigint NOT NULL,
    disposition_type text COLLATE "C" NOT NULL,
    state text COLLATE "C" NOT NULL DEFAULT 'PENDING',
    actor_principal_pk bigint,
    reason_code text COLLATE "C" NOT NULL,
    result_digest bytea,
    effective_at timestamptz NOT NULL,
    completed_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    CONSTRAINT risk_dispositions_pkey PRIMARY KEY (risk_disposition_pk),
    CONSTRAINT risk_dispositions_id_key UNIQUE (risk_disposition_id),
    CONSTRAINT risk_dispositions_id_v4_ck CHECK (public.iam_uuid_is_v4(risk_disposition_id)),
    CONSTRAINT risk_dispositions_assessment_fk FOREIGN KEY (risk_assessment_pk)
        REFERENCES public.risk_assessments (risk_assessment_pk) ON DELETE RESTRICT,
    CONSTRAINT risk_dispositions_actor_fk FOREIGN KEY (actor_principal_pk)
        REFERENCES public.iam_principals (principal_pk) ON DELETE RESTRICT,
    CONSTRAINT risk_dispositions_type_ck CHECK (
        disposition_type IN ('ALLOW', 'CHALLENGE', 'STEP_UP', 'WAIT', 'DENY', 'FREEZE', 'OPEN_CASE', 'NOTIFY')
    ),
    CONSTRAINT risk_dispositions_state_ck CHECK (
        state IN ('PENDING', 'EXECUTING', 'SUCCEEDED', 'FAILED', 'CANCELLED')
    ),
    CONSTRAINT risk_dispositions_reason_ck CHECK (
        pg_catalog.length(reason_code) BETWEEN 1 AND 96
        AND reason_code ~ '^[A-Z][A-Z0-9_]*$'
    ),
    CONSTRAINT risk_dispositions_digest_ck CHECK (
        result_digest IS NULL OR pg_catalog.octet_length(result_digest) = 32
    ),
    CONSTRAINT risk_dispositions_completion_ck CHECK (
        (state IN ('SUCCEEDED', 'FAILED', 'CANCELLED')) = (completed_at IS NOT NULL)
    ),
    CONSTRAINT risk_dispositions_time_ck CHECK (
        effective_at >= created_at AND (completed_at IS NULL OR completed_at >= effective_at)
    )
);

COMMENT ON TABLE public.risk_dispositions IS
    'Execution record for allow, challenge, denial, freeze, review and notification dispositions; S3.';

CREATE INDEX risk_dispositions_assessment_state_idx
    ON public.risk_dispositions (risk_assessment_pk, state, effective_at);

CREATE TABLE public.risk_cases (
    risk_case_pk bigint GENERATED ALWAYS AS IDENTITY,
    risk_case_id uuid NOT NULL DEFAULT pg_catalog.gen_random_uuid(),
    case_type text COLLATE "C" NOT NULL,
    severity text COLLATE "C" NOT NULL,
    status text COLLATE "C" NOT NULL DEFAULT 'OPEN',
    owner_principal_pk bigint,
    tenant_pk bigint,
    legal_hold_pk bigint,
    summary_digest bytea NOT NULL,
    opened_at timestamptz NOT NULL,
    closed_at timestamptz,
    row_version bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    CONSTRAINT risk_cases_pkey PRIMARY KEY (risk_case_pk),
    CONSTRAINT risk_cases_id_key UNIQUE (risk_case_id),
    CONSTRAINT risk_cases_id_v4_ck CHECK (public.iam_uuid_is_v4(risk_case_id)),
    CONSTRAINT risk_cases_owner_fk FOREIGN KEY (owner_principal_pk)
        REFERENCES public.iam_principals (principal_pk) ON DELETE RESTRICT,
    CONSTRAINT risk_cases_tenant_fk FOREIGN KEY (tenant_pk)
        REFERENCES public.org_tenants (tenant_pk) ON DELETE RESTRICT,
    CONSTRAINT risk_cases_hold_fk FOREIGN KEY (legal_hold_pk)
        REFERENCES public.priv_legal_holds (legal_hold_pk) ON DELETE RESTRICT,
    CONSTRAINT risk_cases_type_ck CHECK (
        case_type IN ('ACCOUNT_TAKEOVER', 'FRAUD', 'ABUSE', 'INSIDER', 'CLIENT_COMPROMISE', 'KEY_COMPROMISE', 'PRIVACY', 'OTHER')
    ),
    CONSTRAINT risk_cases_severity_ck CHECK (
        severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')
    ),
    CONSTRAINT risk_cases_status_ck CHECK (
        status IN ('OPEN', 'TRIAGED', 'INVESTIGATING', 'CONTAINED', 'MONITORING', 'CLOSED', 'DISMISSED')
    ),
    CONSTRAINT risk_cases_summary_digest_ck CHECK (pg_catalog.octet_length(summary_digest) = 32),
    CONSTRAINT risk_cases_closed_ck CHECK (
        (status IN ('CLOSED', 'DISMISSED')) = (closed_at IS NOT NULL)
    ),
    CONSTRAINT risk_cases_version_ck CHECK (row_version > 0),
    CONSTRAINT risk_cases_time_ck CHECK (
        opened_at <= created_at AND updated_at >= created_at
        AND (closed_at IS NULL OR closed_at >= opened_at)
    )
);

COMMENT ON TABLE public.risk_cases IS
    'Security or fraud investigation case with owner, severity, optional legal hold and explicit lifecycle; S3.';

CREATE INDEX risk_cases_status_severity_idx
    ON public.risk_cases (status, severity, opened_at);
CREATE INDEX risk_cases_owner_idx
    ON public.risk_cases (owner_principal_pk, status)
    WHERE owner_principal_pk IS NOT NULL;

CREATE TRIGGER risk_cases_immutable_trg
BEFORE UPDATE ON public.risk_cases
FOR EACH ROW EXECUTE FUNCTION public.iam_reject_column_changes(
    'risk_case_pk', 'risk_case_id', 'case_type', 'tenant_pk',
    'summary_digest', 'opened_at', 'created_at'
);

CREATE TRIGGER risk_cases_version_trg
BEFORE UPDATE ON public.risk_cases
FOR EACH ROW EXECUTE FUNCTION public.iam_guard_nondecreasing_bigint('row_version');

CREATE TABLE public.risk_case_entities (
    risk_case_entity_pk bigint GENERATED ALWAYS AS IDENTITY,
    risk_case_pk bigint NOT NULL,
    entity_type text COLLATE "C" NOT NULL,
    principal_pk bigint,
    client_pk bigint,
    tenant_pk bigint,
    resource_pk bigint,
    risk_signal_pk bigint,
    external_entity_digest bytea,
    role_in_case text COLLATE "C" NOT NULL,
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    CONSTRAINT risk_case_entities_pkey PRIMARY KEY (risk_case_entity_pk),
    CONSTRAINT risk_case_entities_case_fk FOREIGN KEY (risk_case_pk)
        REFERENCES public.risk_cases (risk_case_pk) ON DELETE RESTRICT,
    CONSTRAINT risk_case_entities_principal_fk FOREIGN KEY (principal_pk)
        REFERENCES public.iam_principals (principal_pk) ON DELETE RESTRICT,
    CONSTRAINT risk_case_entities_client_fk FOREIGN KEY (client_pk)
        REFERENCES public.app_clients (client_pk) ON DELETE RESTRICT,
    CONSTRAINT risk_case_entities_tenant_fk FOREIGN KEY (tenant_pk)
        REFERENCES public.org_tenants (tenant_pk) ON DELETE RESTRICT,
    CONSTRAINT risk_case_entities_resource_fk FOREIGN KEY (resource_pk)
        REFERENCES public.authz_resources (resource_pk) ON DELETE RESTRICT,
    CONSTRAINT risk_case_entities_signal_fk FOREIGN KEY (risk_signal_pk)
        REFERENCES public.risk_signals (risk_signal_pk) ON DELETE RESTRICT,
    CONSTRAINT risk_case_entities_shape_ck CHECK (
        (entity_type = 'PRINCIPAL' AND principal_pk IS NOT NULL AND client_pk IS NULL
            AND tenant_pk IS NULL AND resource_pk IS NULL AND risk_signal_pk IS NULL AND external_entity_digest IS NULL)
        OR (entity_type = 'CLIENT' AND principal_pk IS NULL AND client_pk IS NOT NULL
            AND tenant_pk IS NULL AND resource_pk IS NULL AND risk_signal_pk IS NULL AND external_entity_digest IS NULL)
        OR (entity_type = 'TENANT' AND principal_pk IS NULL AND client_pk IS NULL
            AND tenant_pk IS NOT NULL AND resource_pk IS NULL AND risk_signal_pk IS NULL AND external_entity_digest IS NULL)
        OR (entity_type = 'RESOURCE' AND principal_pk IS NULL AND client_pk IS NULL
            AND tenant_pk IS NULL AND resource_pk IS NOT NULL AND risk_signal_pk IS NULL AND external_entity_digest IS NULL)
        OR (entity_type = 'SIGNAL' AND principal_pk IS NULL AND client_pk IS NULL
            AND tenant_pk IS NULL AND resource_pk IS NULL AND risk_signal_pk IS NOT NULL AND external_entity_digest IS NULL)
        OR (entity_type IN ('DEVICE', 'NETWORK', 'EXTERNAL') AND principal_pk IS NULL
            AND client_pk IS NULL AND tenant_pk IS NULL AND resource_pk IS NULL AND risk_signal_pk IS NULL
            AND external_entity_digest IS NOT NULL AND pg_catalog.octet_length(external_entity_digest) = 32)
    ),
    CONSTRAINT risk_case_entities_role_ck CHECK (
        role_in_case IN ('SUBJECT', 'ACTOR', 'VICTIM', 'INDICATOR', 'EVIDENCE', 'AFFECTED')
    )
);

COMMENT ON TABLE public.risk_case_entities IS
    'Typed entities and evidence linked to a risk case; opaque external entities use keyed digests; S3.';

CREATE INDEX risk_case_entities_case_role_idx
    ON public.risk_case_entities (risk_case_pk, role_in_case, risk_case_entity_pk);
CREATE INDEX risk_case_entities_principal_idx
    ON public.risk_case_entities (principal_pk, risk_case_pk)
    WHERE principal_pk IS NOT NULL;

CREATE TABLE public.risk_case_actions (
    risk_case_action_pk bigint GENERATED ALWAYS AS IDENTITY,
    risk_case_pk bigint NOT NULL,
    action_type text COLLATE "C" NOT NULL,
    actor_principal_pk bigint NOT NULL,
    reason_code text COLLATE "C" NOT NULL,
    before_digest bytea,
    after_digest bytea,
    evidence_reference text COLLATE "C",
    occurred_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    CONSTRAINT risk_case_actions_pkey PRIMARY KEY (risk_case_action_pk),
    CONSTRAINT risk_case_actions_case_fk FOREIGN KEY (risk_case_pk)
        REFERENCES public.risk_cases (risk_case_pk) ON DELETE RESTRICT,
    CONSTRAINT risk_case_actions_actor_fk FOREIGN KEY (actor_principal_pk)
        REFERENCES public.iam_principals (principal_pk) ON DELETE RESTRICT,
    CONSTRAINT risk_case_actions_type_ck CHECK (
        action_type IN ('TRIAGE', 'ASSIGN', 'INVESTIGATE', 'CONTAIN', 'NOTIFY', 'APPEAL', 'OVERTURN', 'CLOSE', 'REOPEN', 'POSTMORTEM')
    ),
    CONSTRAINT risk_case_actions_reason_ck CHECK (
        pg_catalog.length(reason_code) BETWEEN 1 AND 96
        AND reason_code ~ '^[A-Z][A-Z0-9_]*$'
    ),
    CONSTRAINT risk_case_actions_before_ck CHECK (
        before_digest IS NULL OR pg_catalog.octet_length(before_digest) = 32
    ),
    CONSTRAINT risk_case_actions_after_ck CHECK (
        after_digest IS NULL OR pg_catalog.octet_length(after_digest) = 32
    ),
    CONSTRAINT risk_case_actions_reference_ck CHECK (
        evidence_reference IS NULL OR pg_catalog.length(evidence_reference) BETWEEN 1 AND 1024
    ),
    CONSTRAINT risk_case_actions_time_ck CHECK (occurred_at <= created_at)
);

COMMENT ON TABLE public.risk_case_actions IS
    'Append-only investigation, containment, appeal and postmortem actions with actor and evidence digests; S3.';

CREATE INDEX risk_case_actions_case_time_idx
    ON public.risk_case_actions (risk_case_pk, occurred_at);

CREATE TRIGGER risk_case_actions_append_only_trg
BEFORE UPDATE OR DELETE ON public.risk_case_actions
FOR EACH ROW EXECUTE FUNCTION public.iam_reject_row_mutation();

CREATE TABLE public.risk_security_signals (
    security_signal_pk bigint GENERATED ALWAYS AS IDENTITY,
    security_signal_id uuid NOT NULL DEFAULT pg_catalog.gen_random_uuid(),
    source_risk_signal_pk bigint,
    source_case_pk bigint,
    subject_principal_pk bigint NOT NULL,
    tenant_pk bigint,
    signal_type text COLLATE "C" NOT NULL,
    severity text COLLATE "C" NOT NULL,
    security_epoch bigint NOT NULL,
    reason_code text COLLATE "C" NOT NULL,
    effective_at timestamptz NOT NULL,
    expires_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    CONSTRAINT risk_security_signals_pkey PRIMARY KEY (security_signal_pk),
    CONSTRAINT risk_security_signals_id_key UNIQUE (security_signal_id),
    CONSTRAINT risk_security_signals_subject_version_key UNIQUE (
        subject_principal_pk, signal_type, security_epoch
    ),
    CONSTRAINT risk_security_signals_id_v4_ck CHECK (public.iam_uuid_is_v4(security_signal_id)),
    CONSTRAINT risk_security_signals_source_signal_fk FOREIGN KEY (source_risk_signal_pk)
        REFERENCES public.risk_signals (risk_signal_pk) ON DELETE RESTRICT,
    CONSTRAINT risk_security_signals_source_case_fk FOREIGN KEY (source_case_pk)
        REFERENCES public.risk_cases (risk_case_pk) ON DELETE RESTRICT,
    CONSTRAINT risk_security_signals_subject_fk FOREIGN KEY (subject_principal_pk)
        REFERENCES public.iam_principals (principal_pk) ON DELETE RESTRICT,
    CONSTRAINT risk_security_signals_tenant_fk FOREIGN KEY (tenant_pk)
        REFERENCES public.org_tenants (tenant_pk) ON DELETE RESTRICT,
    CONSTRAINT risk_security_signals_source_ck CHECK (
        source_risk_signal_pk IS NOT NULL OR source_case_pk IS NOT NULL
    ),
    CONSTRAINT risk_security_signals_type_ck CHECK (
        signal_type IN ('ACCOUNT_COMPROMISED', 'ASSURANCE_CHANGED', 'SESSION_REVOKED', 'TOKEN_FAMILY_COMPROMISED', 'CLIENT_COMPROMISED', 'RISK_ESCALATED', 'ACCESS_RESTORED')
    ),
    CONSTRAINT risk_security_signals_severity_ck CHECK (
        severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')
    ),
    CONSTRAINT risk_security_signals_epoch_ck CHECK (security_epoch > 0),
    CONSTRAINT risk_security_signals_reason_ck CHECK (
        pg_catalog.length(reason_code) BETWEEN 1 AND 96
        AND reason_code ~ '^[A-Z][A-Z0-9_]*$'
    ),
    CONSTRAINT risk_security_signals_time_ck CHECK (
        effective_at <= created_at AND (expires_at IS NULL OR expires_at > effective_at)
    )
);

COMMENT ON TABLE public.risk_security_signals IS
    'Append-only continuous security signal produced by risk response with monotonic subject epoch; S3.';

CREATE INDEX risk_security_signals_subject_idx
    ON public.risk_security_signals (subject_principal_pk, security_epoch DESC);
CREATE INDEX risk_security_signals_tenant_time_idx
    ON public.risk_security_signals (tenant_pk, effective_at DESC)
    WHERE tenant_pk IS NOT NULL;

CREATE TRIGGER risk_security_signals_append_only_trg
BEFORE UPDATE OR DELETE ON public.risk_security_signals
FOR EACH ROW EXECUTE FUNCTION public.iam_reject_row_mutation();

CREATE TABLE public.ctrl_change_sets (
    change_set_pk bigint GENERATED ALWAYS AS IDENTITY,
    change_set_id uuid NOT NULL DEFAULT pg_catalog.gen_random_uuid(),
    change_type text COLLATE "C" NOT NULL,
    scope_node_pk bigint NOT NULL,
    environment text COLLATE "C" NOT NULL,
    state text COLLATE "C" NOT NULL DEFAULT 'DRAFT',
    submitter_principal_pk bigint NOT NULL,
    content_hash bytea NOT NULL,
    change_version bigint NOT NULL DEFAULT 1,
    submitted_at timestamptz,
    activated_at timestamptz,
    row_version bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    CONSTRAINT ctrl_change_sets_pkey PRIMARY KEY (change_set_pk),
    CONSTRAINT ctrl_change_sets_id_key UNIQUE (change_set_id),
    CONSTRAINT ctrl_change_sets_id_v4_ck CHECK (public.iam_uuid_is_v4(change_set_id)),
    CONSTRAINT ctrl_change_sets_scope_fk FOREIGN KEY (scope_node_pk)
        REFERENCES public.authz_scope_nodes (scope_node_pk) ON DELETE RESTRICT,
    CONSTRAINT ctrl_change_sets_submitter_fk FOREIGN KEY (submitter_principal_pk)
        REFERENCES public.iam_principals (principal_pk) ON DELETE RESTRICT,
    CONSTRAINT ctrl_change_sets_type_ck CHECK (
        change_type IN ('CLIENT', 'IDENTITY_PROVIDER', 'POLICY', 'RISK_RULE', 'RISK_MODEL', 'KEY', 'RETENTION', 'WEBHOOK', 'OTHER')
    ),
    CONSTRAINT ctrl_change_sets_environment_ck CHECK (
        environment IN ('DEVELOPMENT', 'TEST', 'STAGING', 'PRODUCTION')
    ),
    CONSTRAINT ctrl_change_sets_state_ck CHECK (
        state IN ('DRAFT', 'VALIDATED', 'APPROVED', 'STAGED', 'ACTIVE', 'DEPRECATED', 'REVOKED', 'REJECTED')
    ),
    CONSTRAINT ctrl_change_sets_hash_ck CHECK (pg_catalog.octet_length(content_hash) = 32),
    CONSTRAINT ctrl_change_sets_versions_ck CHECK (change_version > 0 AND row_version > 0),
    CONSTRAINT ctrl_change_sets_submission_ck CHECK (
        (state = 'DRAFT' AND submitted_at IS NULL)
        OR (state <> 'DRAFT' AND submitted_at IS NOT NULL)
    ),
    CONSTRAINT ctrl_change_sets_activation_ck CHECK (
        (state = 'ACTIVE') = (activated_at IS NOT NULL)
    ),
    CONSTRAINT ctrl_change_sets_time_ck CHECK (
        updated_at >= created_at
        AND (submitted_at IS NULL OR submitted_at >= created_at)
        AND (activated_at IS NULL OR activated_at >= submitted_at)
    )
);

COMMENT ON TABLE public.ctrl_change_sets IS
    'Control-plane change aggregate from draft through validation, approval, staging and activation; S3.';

CREATE INDEX ctrl_change_sets_state_environment_idx
    ON public.ctrl_change_sets (state, environment, updated_at);
CREATE INDEX ctrl_change_sets_submitter_idx
    ON public.ctrl_change_sets (submitter_principal_pk, created_at DESC);

CREATE TRIGGER ctrl_change_sets_immutable_trg
BEFORE UPDATE ON public.ctrl_change_sets
FOR EACH ROW EXECUTE FUNCTION public.iam_reject_column_changes(
    'change_set_pk', 'change_set_id', 'change_type', 'scope_node_pk',
    'environment', 'submitter_principal_pk', 'content_hash', 'created_at'
);

CREATE TRIGGER ctrl_change_sets_versions_trg
BEFORE UPDATE ON public.ctrl_change_sets
FOR EACH ROW EXECUTE FUNCTION public.iam_guard_nondecreasing_bigint('change_version', 'row_version');

CREATE TABLE public.ctrl_artifacts (
    artifact_pk bigint GENERATED ALWAYS AS IDENTITY,
    artifact_id uuid NOT NULL DEFAULT pg_catalog.gen_random_uuid(),
    artifact_type text COLLATE "C" NOT NULL,
    artifact_code text COLLATE "C" NOT NULL,
    scope_node_pk bigint NOT NULL,
    state text COLLATE "C" NOT NULL DEFAULT 'ACTIVE',
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    CONSTRAINT ctrl_artifacts_pkey PRIMARY KEY (artifact_pk),
    CONSTRAINT ctrl_artifacts_id_key UNIQUE (artifact_id),
    CONSTRAINT ctrl_artifacts_code_key UNIQUE (scope_node_pk, artifact_type, artifact_code),
    CONSTRAINT ctrl_artifacts_id_v4_ck CHECK (public.iam_uuid_is_v4(artifact_id)),
    CONSTRAINT ctrl_artifacts_scope_fk FOREIGN KEY (scope_node_pk)
        REFERENCES public.authz_scope_nodes (scope_node_pk) ON DELETE RESTRICT,
    CONSTRAINT ctrl_artifacts_type_ck CHECK (
        artifact_type IN ('CLIENT_CONFIG', 'IDP_CONFIG', 'POLICY', 'RISK_RULE', 'RISK_MODEL', 'KEY_POLICY', 'RETENTION_POLICY', 'WEBHOOK_CONFIG')
    ),
    CONSTRAINT ctrl_artifacts_code_ck CHECK (
        pg_catalog.length(artifact_code) BETWEEN 1 AND 128
        AND artifact_code ~ '^[A-Za-z][A-Za-z0-9_.:-]*$'
    ),
    CONSTRAINT ctrl_artifacts_state_ck CHECK (state IN ('ACTIVE', 'RETIRED'))
);

COMMENT ON TABLE public.ctrl_artifacts IS
    'Stable control-plane artifact identity; content is stored only in immutable versions; S2.';

CREATE TABLE public.ctrl_artifact_versions (
    artifact_version_pk bigint GENERATED ALWAYS AS IDENTITY,
    artifact_version_id uuid NOT NULL DEFAULT pg_catalog.gen_random_uuid(),
    artifact_pk bigint NOT NULL,
    change_set_pk bigint NOT NULL,
    version_no bigint NOT NULL,
    schema_version integer NOT NULL,
    content jsonb NOT NULL,
    content_hash bytea NOT NULL,
    previous_version_pk bigint,
    state text COLLATE "C" NOT NULL DEFAULT 'DRAFT',
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    CONSTRAINT ctrl_artifact_versions_pkey PRIMARY KEY (artifact_version_pk),
    CONSTRAINT ctrl_artifact_versions_id_key UNIQUE (artifact_version_id),
    CONSTRAINT ctrl_artifact_versions_number_key UNIQUE (artifact_pk, version_no),
    CONSTRAINT ctrl_artifact_versions_hash_key UNIQUE (artifact_pk, content_hash),
    CONSTRAINT ctrl_artifact_versions_id_v4_ck CHECK (public.iam_uuid_is_v4(artifact_version_id)),
    CONSTRAINT ctrl_artifact_versions_artifact_fk FOREIGN KEY (artifact_pk)
        REFERENCES public.ctrl_artifacts (artifact_pk) ON DELETE RESTRICT,
    CONSTRAINT ctrl_artifact_versions_change_set_fk FOREIGN KEY (change_set_pk)
        REFERENCES public.ctrl_change_sets (change_set_pk) ON DELETE RESTRICT,
    CONSTRAINT ctrl_artifact_versions_previous_fk FOREIGN KEY (previous_version_pk)
        REFERENCES public.ctrl_artifact_versions (artifact_version_pk) ON DELETE RESTRICT,
    CONSTRAINT ctrl_artifact_versions_no_self_ck CHECK (
        previous_version_pk IS NULL OR previous_version_pk <> artifact_version_pk
    ),
    CONSTRAINT ctrl_artifact_versions_number_ck CHECK (version_no > 0),
    CONSTRAINT ctrl_artifact_versions_content_ck CHECK (
        schema_version > 0 AND pg_catalog.jsonb_typeof(content) = 'object'
        AND pg_catalog.octet_length(content::text) <= 1048576
    ),
    CONSTRAINT ctrl_artifact_versions_hash_ck CHECK (pg_catalog.octet_length(content_hash) = 32),
    CONSTRAINT ctrl_artifact_versions_state_ck CHECK (
        state IN ('DRAFT', 'VALIDATED', 'APPROVED', 'REJECTED', 'RETIRED')
    )
);

COMMENT ON TABLE public.ctrl_artifact_versions IS
    'Immutable-version control artifact content; secrets are prohibited and JSON is schema-versioned and bounded; S3.';

CREATE INDEX ctrl_artifact_versions_change_set_idx
    ON public.ctrl_artifact_versions (change_set_pk, state);

CREATE TRIGGER ctrl_artifact_versions_immutable_trg
BEFORE UPDATE ON public.ctrl_artifact_versions
FOR EACH ROW
WHEN (OLD.state <> 'DRAFT')
EXECUTE FUNCTION public.iam_reject_column_changes(
    'artifact_version_pk', 'artifact_version_id', 'artifact_pk',
    'change_set_pk', 'version_no', 'schema_version', 'content',
    'content_hash', 'previous_version_pk', 'created_at'
);

CREATE TABLE public.ctrl_validations (
    validation_pk bigint GENERATED ALWAYS AS IDENTITY,
    change_set_pk bigint NOT NULL,
    artifact_version_pk bigint,
    validation_type text COLLATE "C" NOT NULL,
    validator_code text COLLATE "C" NOT NULL,
    result text COLLATE "C" NOT NULL,
    findings_schema_version integer NOT NULL,
    findings jsonb NOT NULL,
    evidence_hash bytea NOT NULL,
    validated_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    CONSTRAINT ctrl_validations_pkey PRIMARY KEY (validation_pk),
    CONSTRAINT ctrl_validations_change_set_fk FOREIGN KEY (change_set_pk)
        REFERENCES public.ctrl_change_sets (change_set_pk) ON DELETE RESTRICT,
    CONSTRAINT ctrl_validations_artifact_version_fk FOREIGN KEY (artifact_version_pk)
        REFERENCES public.ctrl_artifact_versions (artifact_version_pk) ON DELETE RESTRICT,
    CONSTRAINT ctrl_validations_type_ck CHECK (
        validation_type IN ('SCHEMA', 'REFERENCE', 'LINT', 'SECURITY', 'UNIT', 'PROPERTY', 'REGRESSION', 'DRY_RUN', 'DRIFT')
    ),
    CONSTRAINT ctrl_validations_validator_ck CHECK (
        pg_catalog.length(validator_code) BETWEEN 1 AND 96
        AND validator_code ~ '^[A-Z][A-Z0-9_.:-]*$'
    ),
    CONSTRAINT ctrl_validations_result_ck CHECK (result IN ('PASS', 'FAIL', 'WARNING', 'ERROR')),
    CONSTRAINT ctrl_validations_findings_ck CHECK (
        findings_schema_version > 0 AND pg_catalog.jsonb_typeof(findings) = 'object'
        AND pg_catalog.octet_length(findings::text) <= 262144
    ),
    CONSTRAINT ctrl_validations_hash_ck CHECK (pg_catalog.octet_length(evidence_hash) = 32),
    CONSTRAINT ctrl_validations_time_ck CHECK (validated_at <= created_at)
);

COMMENT ON TABLE public.ctrl_validations IS
    'Append-only schema, lint, security, test, dry-run and drift validation evidence; S3.';

CREATE INDEX ctrl_validations_change_set_type_idx
    ON public.ctrl_validations (change_set_pk, validation_type, validated_at DESC);

CREATE TRIGGER ctrl_validations_append_only_trg
BEFORE UPDATE OR DELETE ON public.ctrl_validations
FOR EACH ROW EXECUTE FUNCTION public.iam_reject_row_mutation();

CREATE TABLE public.ctrl_approvals (
    approval_pk bigint GENERATED ALWAYS AS IDENTITY,
    approval_id uuid NOT NULL DEFAULT pg_catalog.gen_random_uuid(),
    change_set_pk bigint NOT NULL,
    approval_stage text COLLATE "C" NOT NULL,
    approver_principal_pk bigint NOT NULL,
    decision text COLLATE "C" NOT NULL,
    reason_code text COLLATE "C" NOT NULL,
    auth_context_pk bigint,
    evidence_digest bytea NOT NULL,
    decided_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    CONSTRAINT ctrl_approvals_pkey PRIMARY KEY (approval_pk),
    CONSTRAINT ctrl_approvals_id_key UNIQUE (approval_id),
    CONSTRAINT ctrl_approvals_stage_approver_key UNIQUE (
        change_set_pk, approval_stage, approver_principal_pk
    ),
    CONSTRAINT ctrl_approvals_id_v4_ck CHECK (public.iam_uuid_is_v4(approval_id)),
    CONSTRAINT ctrl_approvals_change_set_fk FOREIGN KEY (change_set_pk)
        REFERENCES public.ctrl_change_sets (change_set_pk) ON DELETE RESTRICT,
    CONSTRAINT ctrl_approvals_approver_fk FOREIGN KEY (approver_principal_pk)
        REFERENCES public.iam_principals (principal_pk) ON DELETE RESTRICT,
    CONSTRAINT ctrl_approvals_auth_context_fk FOREIGN KEY (auth_context_pk)
        REFERENCES public.auth_contexts (auth_context_pk) ON DELETE RESTRICT,
    CONSTRAINT ctrl_approvals_stage_ck CHECK (
        approval_stage IN ('OWNER', 'SECURITY', 'PRIVACY', 'OPERATIONS', 'FINAL', 'EMERGENCY_REVIEW')
    ),
    CONSTRAINT ctrl_approvals_decision_ck CHECK (
        decision IN ('APPROVE', 'REJECT', 'ABSTAIN')
    ),
    CONSTRAINT ctrl_approvals_reason_ck CHECK (
        pg_catalog.length(reason_code) BETWEEN 1 AND 96
        AND reason_code ~ '^[A-Z][A-Z0-9_]*$'
    ),
    CONSTRAINT ctrl_approvals_evidence_ck CHECK (pg_catalog.octet_length(evidence_digest) = 32),
    CONSTRAINT ctrl_approvals_time_ck CHECK (decided_at <= created_at)
);

COMMENT ON TABLE public.ctrl_approvals IS
    'Append-only staged approval decision; submitter/approver separation and approval quorum are deferred to 110; S3.';

CREATE INDEX ctrl_approvals_change_set_decision_idx
    ON public.ctrl_approvals (change_set_pk, approval_stage, decision);

CREATE TRIGGER ctrl_approvals_append_only_trg
BEFORE UPDATE OR DELETE ON public.ctrl_approvals
FOR EACH ROW EXECUTE FUNCTION public.iam_reject_row_mutation();

CREATE TABLE public.ctrl_releases (
    release_pk bigint GENERATED ALWAYS AS IDENTITY,
    release_id uuid NOT NULL DEFAULT pg_catalog.gen_random_uuid(),
    change_set_pk bigint NOT NULL,
    artifact_version_pk bigint NOT NULL,
    environment text COLLATE "C" NOT NULL,
    release_no bigint NOT NULL,
    status text COLLATE "C" NOT NULL DEFAULT 'STAGED',
    rollback_of_release_pk bigint,
    content_hash bytea NOT NULL,
    staged_at timestamptz NOT NULL,
    activated_at timestamptz,
    completed_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    CONSTRAINT ctrl_releases_pkey PRIMARY KEY (release_pk),
    CONSTRAINT ctrl_releases_id_key UNIQUE (release_id),
    CONSTRAINT ctrl_releases_number_key UNIQUE (artifact_version_pk, environment, release_no),
    CONSTRAINT ctrl_releases_id_v4_ck CHECK (public.iam_uuid_is_v4(release_id)),
    CONSTRAINT ctrl_releases_change_set_fk FOREIGN KEY (change_set_pk)
        REFERENCES public.ctrl_change_sets (change_set_pk) ON DELETE RESTRICT,
    CONSTRAINT ctrl_releases_artifact_version_fk FOREIGN KEY (artifact_version_pk)
        REFERENCES public.ctrl_artifact_versions (artifact_version_pk) ON DELETE RESTRICT,
    CONSTRAINT ctrl_releases_rollback_fk FOREIGN KEY (rollback_of_release_pk)
        REFERENCES public.ctrl_releases (release_pk) ON DELETE RESTRICT,
    CONSTRAINT ctrl_releases_no_self_ck CHECK (
        rollback_of_release_pk IS NULL OR rollback_of_release_pk <> release_pk
    ),
    CONSTRAINT ctrl_releases_environment_ck CHECK (
        environment IN ('DEVELOPMENT', 'TEST', 'STAGING', 'PRODUCTION')
    ),
    CONSTRAINT ctrl_releases_number_ck CHECK (release_no > 0),
    CONSTRAINT ctrl_releases_status_ck CHECK (
        status IN ('STAGED', 'CANARY', 'ACTIVE', 'SUCCEEDED', 'FAILED', 'ROLLED_BACK', 'REVOKED')
    ),
    CONSTRAINT ctrl_releases_hash_ck CHECK (pg_catalog.octet_length(content_hash) = 32),
    CONSTRAINT ctrl_releases_activation_ck CHECK (
        (status = 'STAGED' AND activated_at IS NULL)
        OR (status <> 'STAGED' AND activated_at IS NOT NULL)
    ),
    CONSTRAINT ctrl_releases_completion_ck CHECK (
        (status IN ('SUCCEEDED', 'FAILED', 'ROLLED_BACK', 'REVOKED')) = (completed_at IS NOT NULL)
    ),
    CONSTRAINT ctrl_releases_time_ck CHECK (
        staged_at >= created_at
        AND (activated_at IS NULL OR activated_at >= staged_at)
        AND (completed_at IS NULL OR completed_at >= activated_at)
    )
);

COMMENT ON TABLE public.ctrl_releases IS
    'Immutable-content environment release; rollback is represented by a new release referencing prior content; S3.';

CREATE INDEX ctrl_releases_environment_status_idx
    ON public.ctrl_releases (environment, status, staged_at);
CREATE INDEX ctrl_releases_change_set_idx
    ON public.ctrl_releases (change_set_pk, release_no);

CREATE TABLE public.ctrl_release_targets (
    release_target_pk bigint GENERATED ALWAYS AS IDENTITY,
    release_pk bigint NOT NULL,
    target_type text COLLATE "C" NOT NULL,
    scope_node_pk bigint,
    tenant_pk bigint,
    client_pk bigint,
    target_key_digest bytea,
    target_weight numeric(6,3) NOT NULL DEFAULT 100,
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    CONSTRAINT ctrl_release_targets_pkey PRIMARY KEY (release_target_pk),
    CONSTRAINT ctrl_release_targets_release_fk FOREIGN KEY (release_pk)
        REFERENCES public.ctrl_releases (release_pk) ON DELETE RESTRICT,
    CONSTRAINT ctrl_release_targets_scope_fk FOREIGN KEY (scope_node_pk)
        REFERENCES public.authz_scope_nodes (scope_node_pk) ON DELETE RESTRICT,
    CONSTRAINT ctrl_release_targets_tenant_fk FOREIGN KEY (tenant_pk)
        REFERENCES public.org_tenants (tenant_pk) ON DELETE RESTRICT,
    CONSTRAINT ctrl_release_targets_client_fk FOREIGN KEY (client_pk)
        REFERENCES public.app_clients (client_pk) ON DELETE RESTRICT,
    CONSTRAINT ctrl_release_targets_shape_ck CHECK (
        (target_type = 'SCOPE' AND scope_node_pk IS NOT NULL AND tenant_pk IS NULL
            AND client_pk IS NULL AND target_key_digest IS NULL)
        OR (target_type = 'TENANT' AND scope_node_pk IS NULL AND tenant_pk IS NOT NULL
            AND client_pk IS NULL AND target_key_digest IS NULL)
        OR (target_type = 'CLIENT' AND scope_node_pk IS NULL AND tenant_pk IS NULL
            AND client_pk IS NOT NULL AND target_key_digest IS NULL)
        OR (target_type IN ('REGION', 'INSTANCE_GROUP') AND scope_node_pk IS NULL
            AND tenant_pk IS NULL AND client_pk IS NULL AND target_key_digest IS NOT NULL
            AND pg_catalog.octet_length(target_key_digest) = 32)
    ),
    CONSTRAINT ctrl_release_targets_weight_ck CHECK (target_weight > 0 AND target_weight <= 100)
);

COMMENT ON TABLE public.ctrl_release_targets IS
    'Typed targets and rollout weights for a control-plane release; S2/S3.';

CREATE INDEX ctrl_release_targets_release_idx
    ON public.ctrl_release_targets (release_pk, target_type);

CREATE TABLE public.ctrl_rollouts (
    rollout_pk bigint GENERATED ALWAYS AS IDENTITY,
    release_target_pk bigint NOT NULL,
    phase_no integer NOT NULL,
    status text COLLATE "C" NOT NULL DEFAULT 'PENDING',
    traffic_percent numeric(6,3) NOT NULL,
    gate_schema_version integer NOT NULL,
    gate_metrics jsonb NOT NULL,
    metrics_hash bytea NOT NULL,
    started_at timestamptz,
    finished_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    CONSTRAINT ctrl_rollouts_pkey PRIMARY KEY (rollout_pk),
    CONSTRAINT ctrl_rollouts_phase_key UNIQUE (release_target_pk, phase_no),
    CONSTRAINT ctrl_rollouts_target_fk FOREIGN KEY (release_target_pk)
        REFERENCES public.ctrl_release_targets (release_target_pk) ON DELETE RESTRICT,
    CONSTRAINT ctrl_rollouts_phase_ck CHECK (phase_no > 0),
    CONSTRAINT ctrl_rollouts_status_ck CHECK (
        status IN ('PENDING', 'RUNNING', 'PAUSED', 'SUCCEEDED', 'FAILED', 'ROLLED_BACK')
    ),
    CONSTRAINT ctrl_rollouts_traffic_ck CHECK (traffic_percent > 0 AND traffic_percent <= 100),
    CONSTRAINT ctrl_rollouts_gate_ck CHECK (
        gate_schema_version > 0 AND pg_catalog.jsonb_typeof(gate_metrics) = 'object'
        AND pg_catalog.octet_length(gate_metrics::text) <= 262144
    ),
    CONSTRAINT ctrl_rollouts_hash_ck CHECK (pg_catalog.octet_length(metrics_hash) = 32),
    CONSTRAINT ctrl_rollouts_started_ck CHECK (
        (status = 'PENDING' AND started_at IS NULL)
        OR (status <> 'PENDING' AND started_at IS NOT NULL)
    ),
    CONSTRAINT ctrl_rollouts_finished_ck CHECK (
        (status IN ('SUCCEEDED', 'FAILED', 'ROLLED_BACK')) = (finished_at IS NOT NULL)
    ),
    CONSTRAINT ctrl_rollouts_time_ck CHECK (
        (started_at IS NULL OR started_at >= created_at)
        AND (finished_at IS NULL OR finished_at >= started_at)
    )
);

COMMENT ON TABLE public.ctrl_rollouts IS
    'Canary rollout phase, traffic percentage and bounded gate metrics for release decisions; S3.';

CREATE INDEX ctrl_rollouts_status_idx
    ON public.ctrl_rollouts (status, started_at, rollout_pk)
    WHERE status IN ('PENDING', 'RUNNING', 'PAUSED');

CREATE TABLE public.ctrl_emergency_actions (
    emergency_action_pk bigint GENERATED ALWAYS AS IDENTITY,
    emergency_action_id uuid NOT NULL DEFAULT pg_catalog.gen_random_uuid(),
    action_type text COLLATE "C" NOT NULL,
    target_type text COLLATE "C" NOT NULL,
    target_reference text COLLATE "C" NOT NULL,
    initiator_principal_pk bigint NOT NULL,
    approver_principal_pk bigint,
    reason_code text COLLATE "C" NOT NULL,
    state text COLLATE "C" NOT NULL DEFAULT 'REQUESTED',
    expires_at timestamptz NOT NULL,
    executed_at timestamptz,
    reviewed_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    CONSTRAINT ctrl_emergency_actions_pkey PRIMARY KEY (emergency_action_pk),
    CONSTRAINT ctrl_emergency_actions_id_key UNIQUE (emergency_action_id),
    CONSTRAINT ctrl_emergency_actions_id_v4_ck CHECK (public.iam_uuid_is_v4(emergency_action_id)),
    CONSTRAINT ctrl_emergency_actions_initiator_fk FOREIGN KEY (initiator_principal_pk)
        REFERENCES public.iam_principals (principal_pk) ON DELETE RESTRICT,
    CONSTRAINT ctrl_emergency_actions_approver_fk FOREIGN KEY (approver_principal_pk)
        REFERENCES public.iam_principals (principal_pk) ON DELETE RESTRICT,
    CONSTRAINT ctrl_emergency_actions_no_self_approval_ck CHECK (
        approver_principal_pk IS NULL OR approver_principal_pk <> initiator_principal_pk
    ),
    CONSTRAINT ctrl_emergency_actions_type_ck CHECK (
        action_type IN ('DISABLE_CLIENT', 'REVOKE_KEY', 'ISOLATE_IDP', 'FORCE_MFA', 'FREEZE_SUBJECTS', 'REVOKE_RELEASE')
    ),
    CONSTRAINT ctrl_emergency_actions_target_type_ck CHECK (
        target_type IN ('CLIENT', 'KEY_VERSION', 'IDENTITY_PROVIDER', 'TENANT', 'PRINCIPAL', 'RELEASE', 'SCOPE')
    ),
    CONSTRAINT ctrl_emergency_actions_target_ck CHECK (
        pg_catalog.length(target_reference) BETWEEN 1 AND 512
        AND target_reference ~ '^[A-Za-z0-9][A-Za-z0-9_.:/-]*$'
    ),
    CONSTRAINT ctrl_emergency_actions_reason_ck CHECK (
        pg_catalog.length(reason_code) BETWEEN 1 AND 96
        AND reason_code ~ '^[A-Z][A-Z0-9_]*$'
    ),
    CONSTRAINT ctrl_emergency_actions_state_ck CHECK (
        state IN ('REQUESTED', 'APPROVED', 'EXECUTED', 'FAILED', 'EXPIRED', 'REVIEWED')
    ),
    CONSTRAINT ctrl_emergency_actions_execution_ck CHECK (
        (state IN ('EXECUTED', 'REVIEWED')) = (executed_at IS NOT NULL)
    ),
    CONSTRAINT ctrl_emergency_actions_review_ck CHECK (
        (state = 'REVIEWED') = (reviewed_at IS NOT NULL)
    ),
    CONSTRAINT ctrl_emergency_actions_time_ck CHECK (
        expires_at > created_at
        AND (executed_at IS NULL OR executed_at >= created_at)
        AND (reviewed_at IS NULL OR reviewed_at >= executed_at)
    )
);

COMMENT ON TABLE public.ctrl_emergency_actions IS
    'Time-bounded emergency control action with separate initiator, approver, execution and post-review evidence; S3.';

CREATE INDEX ctrl_emergency_actions_open_idx
    ON public.ctrl_emergency_actions (expires_at, emergency_action_pk)
    WHERE state IN ('REQUESTED', 'APPROVED');

CREATE TABLE public.ctrl_breakglass_grants (
    breakglass_grant_pk bigint GENERATED ALWAYS AS IDENTITY,
    breakglass_grant_id uuid NOT NULL DEFAULT pg_catalog.gen_random_uuid(),
    principal_pk bigint NOT NULL,
    scope_node_pk bigint NOT NULL,
    requested_by_principal_pk bigint NOT NULL,
    approved_by_principal_pk bigint NOT NULL,
    reason_code text COLLATE "C" NOT NULL,
    permission_set_digest bytea NOT NULL,
    state text COLLATE "C" NOT NULL DEFAULT 'ACTIVE',
    valid_from timestamptz NOT NULL,
    valid_until timestamptz NOT NULL,
    revoked_at timestamptz,
    reviewed_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    CONSTRAINT ctrl_breakglass_grants_pkey PRIMARY KEY (breakglass_grant_pk),
    CONSTRAINT ctrl_breakglass_grants_id_key UNIQUE (breakglass_grant_id),
    CONSTRAINT ctrl_breakglass_grants_id_v4_ck CHECK (public.iam_uuid_is_v4(breakglass_grant_id)),
    CONSTRAINT ctrl_breakglass_grants_principal_fk FOREIGN KEY (principal_pk)
        REFERENCES public.iam_principals (principal_pk) ON DELETE RESTRICT,
    CONSTRAINT ctrl_breakglass_grants_scope_fk FOREIGN KEY (scope_node_pk)
        REFERENCES public.authz_scope_nodes (scope_node_pk) ON DELETE RESTRICT,
    CONSTRAINT ctrl_breakglass_grants_requester_fk FOREIGN KEY (requested_by_principal_pk)
        REFERENCES public.iam_principals (principal_pk) ON DELETE RESTRICT,
    CONSTRAINT ctrl_breakglass_grants_approver_fk FOREIGN KEY (approved_by_principal_pk)
        REFERENCES public.iam_principals (principal_pk) ON DELETE RESTRICT,
    CONSTRAINT ctrl_breakglass_grants_separation_ck CHECK (
        requested_by_principal_pk <> approved_by_principal_pk
        AND principal_pk <> approved_by_principal_pk
    ),
    CONSTRAINT ctrl_breakglass_grants_reason_ck CHECK (
        pg_catalog.length(reason_code) BETWEEN 1 AND 96
        AND reason_code ~ '^[A-Z][A-Z0-9_]*$'
    ),
    CONSTRAINT ctrl_breakglass_grants_digest_ck CHECK (
        pg_catalog.octet_length(permission_set_digest) = 32
    ),
    CONSTRAINT ctrl_breakglass_grants_state_ck CHECK (
        state IN ('ACTIVE', 'EXPIRED', 'REVOKED', 'REVIEWED')
    ),
    CONSTRAINT ctrl_breakglass_grants_revocation_ck CHECK (
        (state = 'REVOKED') = (revoked_at IS NOT NULL)
    ),
    CONSTRAINT ctrl_breakglass_grants_review_ck CHECK (
        (state = 'REVIEWED') = (reviewed_at IS NOT NULL)
    ),
    CONSTRAINT ctrl_breakglass_grants_time_ck CHECK (
        valid_from >= created_at AND valid_until > valid_from
        AND (revoked_at IS NULL OR revoked_at >= valid_from)
        AND (reviewed_at IS NULL OR reviewed_at >= valid_from)
    )
);

COMMENT ON TABLE public.ctrl_breakglass_grants IS
    'Minimal, approved and automatically expiring break-glass grant requiring post-use review; S3.';

CREATE INDEX ctrl_breakglass_grants_active_idx
    ON public.ctrl_breakglass_grants (valid_until, principal_pk)
    WHERE state = 'ACTIVE';

CREATE TABLE public.ctrl_breakglass_uses (
    breakglass_use_pk bigint GENERATED ALWAYS AS IDENTITY,
    breakglass_grant_pk bigint NOT NULL,
    decision_pk bigint,
    action_code text COLLATE "C" NOT NULL,
    object_reference_digest bytea NOT NULL,
    trace_id uuid NOT NULL,
    result text COLLATE "C" NOT NULL,
    occurred_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    CONSTRAINT ctrl_breakglass_uses_pkey PRIMARY KEY (breakglass_use_pk),
    CONSTRAINT ctrl_breakglass_uses_grant_fk FOREIGN KEY (breakglass_grant_pk)
        REFERENCES public.ctrl_breakglass_grants (breakglass_grant_pk) ON DELETE RESTRICT,
    CONSTRAINT ctrl_breakglass_uses_decision_fk FOREIGN KEY (decision_pk)
        REFERENCES public.authz_decisions (decision_pk) ON DELETE RESTRICT,
    CONSTRAINT ctrl_breakglass_uses_action_ck CHECK (
        pg_catalog.length(action_code) BETWEEN 1 AND 96
        AND action_code ~ '^[A-Z][A-Z0-9_.:-]*$'
    ),
    CONSTRAINT ctrl_breakglass_uses_object_digest_ck CHECK (
        pg_catalog.octet_length(object_reference_digest) = 32
    ),
    CONSTRAINT ctrl_breakglass_uses_trace_v4_ck CHECK (public.iam_uuid_is_v4(trace_id)),
    CONSTRAINT ctrl_breakglass_uses_result_ck CHECK (
        result IN ('SUCCEEDED', 'DENIED', 'FAILED')
    ),
    CONSTRAINT ctrl_breakglass_uses_time_ck CHECK (occurred_at <= created_at)
);

COMMENT ON TABLE public.ctrl_breakglass_uses IS
    'Append-only, alertable use of break-glass authority linked to authorization decision and trace; S3.';

CREATE INDEX ctrl_breakglass_uses_grant_time_idx
    ON public.ctrl_breakglass_uses (breakglass_grant_pk, occurred_at);

CREATE TRIGGER ctrl_breakglass_uses_append_only_trg
BEFORE UPDATE OR DELETE ON public.ctrl_breakglass_uses
FOR EACH ROW EXECUTE FUNCTION public.iam_reject_row_mutation();

CREATE TABLE public.key_crypto_keys (
    crypto_key_pk bigint GENERATED ALWAYS AS IDENTITY,
    crypto_key_id uuid NOT NULL DEFAULT pg_catalog.gen_random_uuid(),
    key_code text COLLATE "C" NOT NULL,
    purpose text COLLATE "C" NOT NULL,
    environment text COLLATE "C" NOT NULL,
    owner_principal_pk bigint NOT NULL,
    algorithm_policy text COLLATE "C" NOT NULL,
    state text COLLATE "C" NOT NULL DEFAULT 'ACTIVE',
    row_version bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    CONSTRAINT key_crypto_keys_pkey PRIMARY KEY (crypto_key_pk),
    CONSTRAINT key_crypto_keys_id_key UNIQUE (crypto_key_id),
    CONSTRAINT key_crypto_keys_code_key UNIQUE (key_code, environment),
    CONSTRAINT key_crypto_keys_id_v4_ck CHECK (public.iam_uuid_is_v4(crypto_key_id)),
    CONSTRAINT key_crypto_keys_owner_fk FOREIGN KEY (owner_principal_pk)
        REFERENCES public.iam_principals (principal_pk) ON DELETE RESTRICT,
    CONSTRAINT key_crypto_keys_code_ck CHECK (
        pg_catalog.length(key_code) BETWEEN 1 AND 96
        AND key_code ~ '^[A-Z][A-Z0-9_.:-]*$'
    ),
    CONSTRAINT key_crypto_keys_purpose_ck CHECK (
        purpose IN ('TOKEN_SIGNING', 'EVENT_SIGNING', 'WEBHOOK_SIGNING', 'DATA_ENCRYPTION', 'BLIND_INDEX', 'CLIENT_AUTH', 'MTLS', 'AUDIT_SIGNING', 'ROOT_TRUST')
    ),
    CONSTRAINT key_crypto_keys_environment_ck CHECK (
        environment IN ('DEVELOPMENT', 'TEST', 'STAGING', 'PRODUCTION')
    ),
    CONSTRAINT key_crypto_keys_algorithm_policy_ck CHECK (
        pg_catalog.length(algorithm_policy) BETWEEN 1 AND 128
        AND algorithm_policy ~ '^[A-Z][A-Z0-9_.:-]*$'
    ),
    CONSTRAINT key_crypto_keys_state_ck CHECK (
        state IN ('ACTIVE', 'SUSPENDED', 'RETIRED')
    ),
    CONSTRAINT key_crypto_keys_version_ck CHECK (row_version > 0),
    CONSTRAINT key_crypto_keys_time_ck CHECK (updated_at >= created_at)
);

COMMENT ON TABLE public.key_crypto_keys IS
    'Logical cryptographic asset with single purpose, environment, owner and algorithm policy; private keys remain in KMS/HSM; S3.';

CREATE INDEX key_crypto_keys_purpose_state_idx
    ON public.key_crypto_keys (purpose, environment, state);

CREATE TABLE public.key_crypto_key_versions (
    crypto_key_version_pk bigint GENERATED ALWAYS AS IDENTITY,
    crypto_key_version_id uuid NOT NULL DEFAULT pg_catalog.gen_random_uuid(),
    crypto_key_pk bigint NOT NULL,
    version_no bigint NOT NULL,
    kms_key_handle text COLLATE "C" NOT NULL,
    issuer_scope text COLLATE "C" NOT NULL,
    key_id text COLLATE "C" NOT NULL,
    algorithm text COLLATE "C" NOT NULL,
    public_key_format text COLLATE "C",
    public_key bytea,
    public_key_fingerprint bytea,
    state text COLLATE "C" NOT NULL DEFAULT 'GENERATED',
    rotated_from_version_pk bigint,
    generated_at timestamptz NOT NULL,
    published_at timestamptz,
    signing_started_at timestamptz,
    verify_only_at timestamptz,
    retired_at timestamptz,
    compromised_at timestamptz,
    revoked_at timestamptz,
    destroyed_at timestamptz,
    not_before timestamptz NOT NULL,
    not_after timestamptz,
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    CONSTRAINT key_crypto_key_versions_pkey PRIMARY KEY (crypto_key_version_pk),
    CONSTRAINT key_crypto_key_versions_id_key UNIQUE (crypto_key_version_id),
    CONSTRAINT key_crypto_key_versions_number_key UNIQUE (crypto_key_pk, version_no),
    CONSTRAINT key_crypto_key_versions_kid_key UNIQUE (issuer_scope, key_id),
    CONSTRAINT key_crypto_key_versions_handle_key UNIQUE (kms_key_handle),
    CONSTRAINT key_crypto_key_versions_id_v4_ck CHECK (public.iam_uuid_is_v4(crypto_key_version_id)),
    CONSTRAINT key_crypto_key_versions_key_fk FOREIGN KEY (crypto_key_pk)
        REFERENCES public.key_crypto_keys (crypto_key_pk) ON DELETE RESTRICT,
    CONSTRAINT key_crypto_key_versions_rotated_from_fk FOREIGN KEY (rotated_from_version_pk)
        REFERENCES public.key_crypto_key_versions (crypto_key_version_pk) ON DELETE RESTRICT,
    CONSTRAINT key_crypto_key_versions_no_self_ck CHECK (
        rotated_from_version_pk IS NULL OR rotated_from_version_pk <> crypto_key_version_pk
    ),
    CONSTRAINT key_crypto_key_versions_number_ck CHECK (version_no > 0),
    CONSTRAINT key_crypto_key_versions_handle_ck CHECK (
        pg_catalog.length(kms_key_handle) BETWEEN 1 AND 512
        AND kms_key_handle ~ '^[A-Za-z0-9][A-Za-z0-9_.:/-]*$'
    ),
    CONSTRAINT key_crypto_key_versions_issuer_ck CHECK (
        pg_catalog.length(issuer_scope) BETWEEN 1 AND 255
    ),
    CONSTRAINT key_crypto_key_versions_key_id_ck CHECK (
        pg_catalog.length(key_id) BETWEEN 1 AND 255
        AND key_id ~ '^[A-Za-z0-9][A-Za-z0-9_.:-]*$'
    ),
    CONSTRAINT key_crypto_key_versions_algorithm_ck CHECK (
        algorithm IN ('RS256', 'PS256', 'ES256', 'ES384', 'EdDSA', 'RSA-OAEP-256', 'A256GCM', 'HMAC-SHA-256')
    ),
    CONSTRAINT key_crypto_key_versions_public_group_ck CHECK (
        (public_key_format IS NULL AND public_key IS NULL AND public_key_fingerprint IS NULL)
        OR (public_key_format IN ('JWK', 'COSE', 'SPKI', 'PEM') AND public_key IS NOT NULL
            AND pg_catalog.octet_length(public_key) BETWEEN 32 AND 65536
            AND public_key_fingerprint IS NOT NULL
            AND pg_catalog.octet_length(public_key_fingerprint) = 32)
    ),
    CONSTRAINT key_crypto_key_versions_state_ck CHECK (
        state IN ('GENERATED', 'PUBLISHED', 'SIGNING_AND_VERIFYING', 'VERIFY_ONLY', 'RETIRED', 'COMPROMISED', 'REVOKED', 'DESTROYED')
    ),
    CONSTRAINT key_crypto_key_versions_state_time_ck CHECK (
        (state = 'GENERATED' AND published_at IS NULL AND signing_started_at IS NULL
            AND verify_only_at IS NULL AND retired_at IS NULL AND compromised_at IS NULL
            AND revoked_at IS NULL AND destroyed_at IS NULL)
        OR (state = 'PUBLISHED' AND published_at IS NOT NULL AND signing_started_at IS NULL
            AND verify_only_at IS NULL AND retired_at IS NULL AND compromised_at IS NULL
            AND revoked_at IS NULL AND destroyed_at IS NULL)
        OR (state = 'SIGNING_AND_VERIFYING' AND published_at IS NOT NULL AND signing_started_at IS NOT NULL
            AND verify_only_at IS NULL AND retired_at IS NULL AND compromised_at IS NULL
            AND revoked_at IS NULL AND destroyed_at IS NULL)
        OR (state = 'VERIFY_ONLY' AND published_at IS NOT NULL AND signing_started_at IS NOT NULL
            AND verify_only_at IS NOT NULL AND retired_at IS NULL AND compromised_at IS NULL
            AND revoked_at IS NULL AND destroyed_at IS NULL)
        OR (state = 'RETIRED' AND retired_at IS NOT NULL AND revoked_at IS NULL AND destroyed_at IS NULL)
        OR (state = 'COMPROMISED' AND compromised_at IS NOT NULL AND revoked_at IS NULL AND destroyed_at IS NULL)
        OR (state = 'REVOKED' AND revoked_at IS NOT NULL AND destroyed_at IS NULL)
        OR (state = 'DESTROYED' AND destroyed_at IS NOT NULL)
    ),
    CONSTRAINT key_crypto_key_versions_validity_ck CHECK (
        generated_at <= created_at AND not_before >= generated_at
        AND (not_after IS NULL OR not_after > not_before)
        AND (published_at IS NULL OR published_at >= generated_at)
        AND (signing_started_at IS NULL OR signing_started_at >= published_at)
        AND (verify_only_at IS NULL OR verify_only_at >= signing_started_at)
        AND (retired_at IS NULL OR retired_at >= generated_at)
        AND (compromised_at IS NULL OR compromised_at >= generated_at)
        AND (revoked_at IS NULL OR revoked_at >= generated_at)
        AND (destroyed_at IS NULL OR destroyed_at >= generated_at)
    )
);

COMMENT ON TABLE public.key_crypto_key_versions IS
    'Cryptographic key version metadata and complete signing/verification/compromise lifecycle; only KMS handle and public key are stored; S4.';

CREATE INDEX key_crypto_key_versions_active_idx
    ON public.key_crypto_key_versions (crypto_key_pk, state, not_after)
    WHERE state IN ('PUBLISHED', 'SIGNING_AND_VERIFYING', 'VERIFY_ONLY');
CREATE INDEX key_crypto_key_versions_expiry_idx
    ON public.key_crypto_key_versions (not_after, crypto_key_version_pk)
    WHERE not_after IS NOT NULL AND state NOT IN ('REVOKED', 'DESTROYED');

CREATE TRIGGER key_crypto_key_versions_immutable_trg
BEFORE UPDATE ON public.key_crypto_key_versions
FOR EACH ROW EXECUTE FUNCTION public.iam_reject_column_changes(
    'crypto_key_version_pk', 'crypto_key_version_id', 'crypto_key_pk',
    'version_no', 'kms_key_handle', 'issuer_scope', 'key_id', 'algorithm',
    'public_key_format', 'public_key', 'public_key_fingerprint',
    'rotated_from_version_pk', 'generated_at', 'not_before', 'not_after', 'created_at'
);

CREATE TABLE public.key_certificates (
    certificate_pk bigint GENERATED ALWAYS AS IDENTITY,
    certificate_id uuid NOT NULL DEFAULT pg_catalog.gen_random_uuid(),
    crypto_key_version_pk bigint NOT NULL,
    issuer_name_digest bytea NOT NULL,
    serial_number bytea NOT NULL,
    fingerprint_sha256 bytea NOT NULL,
    subject_name_digest bytea NOT NULL,
    certificate_der bytea NOT NULL,
    state text COLLATE "C" NOT NULL DEFAULT 'ISSUED',
    issued_at timestamptz NOT NULL,
    not_before timestamptz NOT NULL,
    not_after timestamptz NOT NULL,
    activated_at timestamptz,
    grace_at timestamptz,
    revoked_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    CONSTRAINT key_certificates_pkey PRIMARY KEY (certificate_pk),
    CONSTRAINT key_certificates_id_key UNIQUE (certificate_id),
    CONSTRAINT key_certificates_issuer_serial_key UNIQUE (issuer_name_digest, serial_number),
    CONSTRAINT key_certificates_fingerprint_key UNIQUE (fingerprint_sha256),
    CONSTRAINT key_certificates_id_v4_ck CHECK (public.iam_uuid_is_v4(certificate_id)),
    CONSTRAINT key_certificates_key_version_fk FOREIGN KEY (crypto_key_version_pk)
        REFERENCES public.key_crypto_key_versions (crypto_key_version_pk) ON DELETE RESTRICT,
    CONSTRAINT key_certificates_issuer_digest_ck CHECK (pg_catalog.octet_length(issuer_name_digest) = 32),
    CONSTRAINT key_certificates_serial_ck CHECK (pg_catalog.octet_length(serial_number) BETWEEN 1 AND 32),
    CONSTRAINT key_certificates_fingerprint_ck CHECK (pg_catalog.octet_length(fingerprint_sha256) = 32),
    CONSTRAINT key_certificates_subject_digest_ck CHECK (pg_catalog.octet_length(subject_name_digest) = 32),
    CONSTRAINT key_certificates_der_ck CHECK (pg_catalog.octet_length(certificate_der) BETWEEN 64 AND 65536),
    CONSTRAINT key_certificates_state_ck CHECK (
        state IN ('ISSUED', 'ACTIVE', 'GRACE', 'EXPIRED', 'REVOKED')
    ),
    CONSTRAINT key_certificates_state_time_ck CHECK (
        (state = 'ISSUED' AND activated_at IS NULL AND grace_at IS NULL AND revoked_at IS NULL)
        OR (state = 'ACTIVE' AND activated_at IS NOT NULL AND grace_at IS NULL AND revoked_at IS NULL)
        OR (state = 'GRACE' AND activated_at IS NOT NULL AND grace_at IS NOT NULL AND revoked_at IS NULL)
        OR (state = 'EXPIRED' AND activated_at IS NOT NULL AND revoked_at IS NULL)
        OR (state = 'REVOKED' AND revoked_at IS NOT NULL)
    ),
    CONSTRAINT key_certificates_time_ck CHECK (
        issued_at <= created_at AND not_before >= issued_at AND not_after > not_before
        AND (activated_at IS NULL OR activated_at >= not_before)
        AND (grace_at IS NULL OR grace_at >= activated_at)
        AND (revoked_at IS NULL OR revoked_at >= issued_at)
    )
);

COMMENT ON TABLE public.key_certificates IS
    'Certificate metadata and public DER with issuer/serial and fingerprint uniqueness and independent lifecycle; S3.';

CREATE INDEX key_certificates_key_state_idx
    ON public.key_certificates (crypto_key_version_pk, state, not_after);
CREATE INDEX key_certificates_expiry_idx
    ON public.key_certificates (not_after, certificate_pk)
    WHERE state IN ('ISSUED', 'ACTIVE', 'GRACE');

CREATE TRIGGER key_certificates_immutable_trg
BEFORE UPDATE ON public.key_certificates
FOR EACH ROW EXECUTE FUNCTION public.iam_reject_column_changes(
    'certificate_pk', 'certificate_id', 'crypto_key_version_pk',
    'issuer_name_digest', 'serial_number', 'fingerprint_sha256',
    'subject_name_digest', 'certificate_der', 'issued_at',
    'not_before', 'not_after', 'created_at'
);

CREATE TABLE public.key_lifecycle_events (
    key_lifecycle_event_pk bigint GENERATED ALWAYS AS IDENTITY,
    key_lifecycle_event_id uuid NOT NULL DEFAULT pg_catalog.gen_random_uuid(),
    crypto_key_pk bigint NOT NULL,
    crypto_key_version_pk bigint,
    certificate_pk bigint,
    event_type text COLLATE "C" NOT NULL,
    actor_principal_pk bigint,
    approval_reference text COLLATE "C",
    evidence_hash bytea NOT NULL,
    previous_state text COLLATE "C",
    new_state text COLLATE "C" NOT NULL,
    occurred_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    CONSTRAINT key_lifecycle_events_pkey PRIMARY KEY (key_lifecycle_event_pk),
    CONSTRAINT key_lifecycle_events_id_key UNIQUE (key_lifecycle_event_id),
    CONSTRAINT key_lifecycle_events_id_v4_ck CHECK (public.iam_uuid_is_v4(key_lifecycle_event_id)),
    CONSTRAINT key_lifecycle_events_key_fk FOREIGN KEY (crypto_key_pk)
        REFERENCES public.key_crypto_keys (crypto_key_pk) ON DELETE RESTRICT,
    CONSTRAINT key_lifecycle_events_key_version_fk FOREIGN KEY (crypto_key_version_pk)
        REFERENCES public.key_crypto_key_versions (crypto_key_version_pk) ON DELETE RESTRICT,
    CONSTRAINT key_lifecycle_events_certificate_fk FOREIGN KEY (certificate_pk)
        REFERENCES public.key_certificates (certificate_pk) ON DELETE RESTRICT,
    CONSTRAINT key_lifecycle_events_actor_fk FOREIGN KEY (actor_principal_pk)
        REFERENCES public.iam_principals (principal_pk) ON DELETE RESTRICT,
    CONSTRAINT key_lifecycle_events_target_ck CHECK (
        crypto_key_version_pk IS NOT NULL OR certificate_pk IS NOT NULL
    ),
    CONSTRAINT key_lifecycle_events_type_ck CHECK (
        event_type IN ('GENERATED', 'PUBLISHED', 'SIGNING_STARTED', 'VERIFY_ONLY', 'ROTATED', 'RETIRED', 'COMPROMISED', 'REVOKED', 'DESTROYED', 'CERTIFICATE_ISSUED', 'CERTIFICATE_ACTIVATED', 'CERTIFICATE_EXPIRED')
    ),
    CONSTRAINT key_lifecycle_events_approval_ck CHECK (
        approval_reference IS NULL OR pg_catalog.length(approval_reference) BETWEEN 1 AND 512
    ),
    CONSTRAINT key_lifecycle_events_hash_ck CHECK (pg_catalog.octet_length(evidence_hash) = 32),
    CONSTRAINT key_lifecycle_events_previous_state_ck CHECK (
        previous_state IS NULL OR previous_state IN (
            'GENERATED', 'PUBLISHED', 'SIGNING_AND_VERIFYING', 'VERIFY_ONLY',
            'RETIRED', 'COMPROMISED', 'REVOKED', 'DESTROYED',
            'ISSUED', 'ACTIVE', 'GRACE', 'EXPIRED'
        )
    ),
    CONSTRAINT key_lifecycle_events_new_state_ck CHECK (
        new_state IN (
            'GENERATED', 'PUBLISHED', 'SIGNING_AND_VERIFYING', 'VERIFY_ONLY',
            'RETIRED', 'COMPROMISED', 'REVOKED', 'DESTROYED',
            'ISSUED', 'ACTIVE', 'GRACE', 'EXPIRED'
        )
    ),
    CONSTRAINT key_lifecycle_events_time_ck CHECK (occurred_at <= created_at)
);

COMMENT ON TABLE public.key_lifecycle_events IS
    'Append-only key and certificate generation, publication, rotation, compromise, revocation and destruction evidence; S3.';

CREATE INDEX key_lifecycle_events_key_time_idx
    ON public.key_lifecycle_events (crypto_key_pk, occurred_at);
CREATE INDEX key_lifecycle_events_version_time_idx
    ON public.key_lifecycle_events (crypto_key_version_pk, occurred_at)
    WHERE crypto_key_version_pk IS NOT NULL;

CREATE TRIGGER key_lifecycle_events_append_only_trg
BEFORE UPDATE OR DELETE ON public.key_lifecycle_events
FOR EACH ROW EXECUTE FUNCTION public.iam_reject_row_mutation();

COMMIT;
